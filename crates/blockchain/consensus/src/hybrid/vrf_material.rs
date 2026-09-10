//! Versioned threshold (VRF) material for the hybrid scheme.
//!
//! [`VrfMaterialProvider`] owns the per-version DKG material (polynomial +
//! optional local share) and every threshold-crypto operation over it: seed
//! signing, proof recovery, and partial/proof verification. State is fully
//! encapsulated behind the provider - the surrounding `HybridScheme` holds a
//! provider and calls its methods, never reaching into the version map. Lifted
//! out of `hybrid.rs` so the material lifecycle reads and tests as one unit;
//! the dependency is one-way (`HybridScheme` -> provider).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use commonware_cryptography::bls12381::primitives::{
    group::Share,
    ops::{self, threshold},
    sharing::Sharing,
    variant::{PartialSignature, Variant},
};
use commonware_parallel::Strategy;
use commonware_utils::{Faults, Participant};

use crate::proof::hybrid_wire::VrfProof;

/// Inputs for verifying a single VRF seed partial against a committee
/// polynomial at a given material version.
pub(crate) struct VrfPartialVerification<'a, V: Variant> {
    pub(crate) version: u64,
    pub(crate) signer: Participant,
    pub(crate) namespace: &'a [u8],
    pub(crate) seed_message: &'a [u8],
    pub(crate) signature: V::Signature,
}

#[derive(Clone, Debug)]
struct VrfMaterial<V: Variant> {
    polynomial: Sharing<V>,
    share: Option<Share>,
}

/// Shared, versioned threshold material used by the VRF sidecar path.
#[derive(Clone, Debug)]
pub struct VrfMaterialProvider<V: Variant> {
    inner: Arc<Mutex<VrfMaterialState<V>>>,
}

#[derive(Clone, Debug)]
struct VrfMaterialState<V: Variant> {
    active_version: u64,
    materials: HashMap<u64, VrfMaterial<V>>,
}

impl<V: Variant> VrfMaterialProvider<V> {
    pub fn new(active_version: u64, polynomial: Sharing<V>, share: Option<Share>) -> Self {
        polynomial.precompute_partial_publics();
        let mut materials = HashMap::new();
        materials.insert(active_version, VrfMaterial { polynomial, share });
        Self {
            inner: Arc::new(Mutex::new(VrfMaterialState {
                active_version,
                materials,
            })),
        }
    }

    pub fn active_version(&self) -> u64 {
        self.with_state(|state| state.active_version)
    }

    pub fn active_polynomial_total(&self) -> Option<u32> {
        self.polynomial_total(self.active_version())
    }

    pub(crate) fn polynomial_total(&self, version: u64) -> Option<u32> {
        self.with_state(|state| {
            state
                .materials
                .get(&version)
                .map(|material| material.polynomial.total().get())
        })
    }

    pub(crate) fn share(&self, version: u64) -> Option<Share> {
        self.with_state(|state| {
            state
                .materials
                .get(&version)
                .and_then(|material| material.share.clone())
        })
    }

    pub(crate) fn public(&self, version: u64) -> Option<V::Public> {
        self.with_state(|state| {
            state
                .materials
                .get(&version)
                .map(|material| *material.polynomial.public())
        })
    }

    /// Partial public key for `index` in the active version's polynomial, or
    /// `None` if there is no active material or the index is out of range.
    /// Lets callers validate a local share without exposing the state map.
    pub(crate) fn partial_public(&self, version: u64, index: Participant) -> Option<V::Public> {
        self.with_state(|state| {
            state
                .materials
                .get(&version)
                .and_then(|material| material.polynomial.partial_public(index).ok())
        })
    }

    pub fn activate(&self, version: u64, polynomial: Sharing<V>, share: Option<Share>) {
        polynomial.precompute_partial_publics();
        self.with_state(|state| {
            state
                .materials
                .insert(version, VrfMaterial { polynomial, share });
            state.active_version = version;
        });
    }

    pub(crate) fn sign_seed(
        &self,
        version: u64,
        namespace: &[u8],
        seed_message: &[u8],
    ) -> Option<V::Signature> {
        self.with_state(|state| {
            let material = state.materials.get(&version)?;
            let share = material.share.as_ref()?;
            let partial = threshold::sign_message::<V>(share, namespace, seed_message).value;
            Some(partial)
        })
    }

    pub(crate) fn recover_proof<M: Faults>(
        &self,
        version: u64,
        seed_partials: &[PartialSignature<V>],
        strategy: &impl Strategy,
    ) -> Option<VrfProof<V>> {
        self.with_state(|state| {
            let material = state.materials.get(&version)?;
            let signature =
                threshold::recover::<V, _, M>(&material.polynomial, seed_partials.iter(), strategy)
                    .ok()?;
            Some(VrfProof {
                material_version: version,
                threshold_signature: signature,
            })
        })
    }

    pub(crate) fn verify_partial(&self, input: VrfPartialVerification<'_, V>) -> bool {
        let VrfPartialVerification {
            version,
            signer,
            namespace,
            seed_message,
            signature,
        } = input;

        self.with_state(|state| {
            let Some(material) = state.materials.get(&version) else {
                return false;
            };
            threshold::verify_message::<V>(
                &material.polynomial,
                namespace,
                seed_message,
                &PartialSignature {
                    index: signer,
                    value: signature,
                },
            )
            .is_ok()
        })
    }

    pub(crate) fn verify_proof(
        &self,
        proof: &VrfProof<V>,
        namespace: &[u8],
        seed_message: &[u8],
    ) -> bool {
        self.with_state(|state| {
            let Some(material) = state.materials.get(&proof.material_version) else {
                return false;
            };
            ops::verify_message::<V>(
                material.polynomial.public(),
                namespace,
                seed_message,
                &proof.threshold_signature,
            )
            .is_ok()
        })
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut VrfMaterialState<V>) -> T) -> T {
        let mut state = self.inner.lock().unwrap_or_else(|poisoned| {
            tracing::error!("VrfMaterialProvider mutex poisoned, recovering");
            poisoned.into_inner()
        });
        f(&mut state)
    }
}
