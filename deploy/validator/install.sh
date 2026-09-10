#!/usr/bin/env bash
set -euo pipefail

OUTBE_ROOT=/opt/outbe-chain
ENV_FILE=$OUTBE_ROOT/validator.env
FEEDER_CONFIG=$OUTBE_ROOT/feeder-public.toml
STORAGE_CONFIG=$OUTBE_ROOT/offchain-storage.toml
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
EXPECTED_SOURCE_DIR=$OUTBE_ROOT/deploy/validator
HELPER=$SOURCE_DIR/outbe-validator-service.py
KEYS_DIR=$OUTBE_ROOT/keys
VALIDATOR_ROOT=$OUTBE_ROOT/validator-0
OCOMP_DOMAIN=$VALIDATOR_ROOT/ocomp/domain-v1

fail() {
  printf '%s\n' "install.sh: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail 'must run as root'
[[ $SOURCE_DIR == "$EXPECTED_SOURCE_DIR" ]] || \
  fail "deployment assets must be installed at $EXPECTED_SOURCE_DIR"

for file in "$ENV_FILE" "$FEEDER_CONFIG" "$STORAGE_CONFIG"; do
  [[ -f $file && ! -L $file ]] || fail "missing local configuration: $file"
  [[ $(stat -c %u "$file") -eq 0 ]] || fail "configuration must be root-owned: $file"
  [[ -z $(find "$file" -maxdepth 0 -perm /022 -print) ]] || \
    fail "configuration must not be group/world writable: $file"
done

seen_names=:
while IFS= read -r line || [[ -n $line ]]; do
  [[ $line =~ ^([A-Z0-9_]+)=\"([^\"]*)\"$ ]] || \
    fail "invalid validator.env line: $line"
  name=${BASH_REMATCH[1]}
  value=${BASH_REMATCH[2]}
  case $name in
    OUTBE_EXTERNAL_IP|OUTBE_CERTIFIED_RPC|OUTBE_VALIDATOR_ADDRESS|\
    OUTBE_BOOTNODES|OUTBE_CONSENSUS_PEERS|OUTBE_MONGODB_IMAGE|\
    OUTBE_ENCLAVE_RUNTIME|OCOMP_CHAIN_ID|OCOMP_GENESIS_HASH|\
    OCOMP_BOOT_NONCE|OCOMP_PROTOCOL_BUNDLE_HASHES)
      ;;
    *)
      fail "unknown validator.env key: $name"
      ;;
  esac
  [[ $seen_names != *":$name:"* ]] || fail "duplicate validator.env key: $name"
  seen_names="${seen_names}${name}:"
  printf -v "$name" '%s' "$value"
  export "$name"
done < "$ENV_FILE"

required=(
  OUTBE_EXTERNAL_IP
  OUTBE_CERTIFIED_RPC
  OUTBE_VALIDATOR_ADDRESS
  OUTBE_BOOTNODES
  OUTBE_CONSENSUS_PEERS
  OUTBE_MONGODB_IMAGE
  OUTBE_ENCLAVE_RUNTIME
  OCOMP_CHAIN_ID
  OCOMP_GENESIS_HASH
  OCOMP_BOOT_NONCE
  OCOMP_PROTOCOL_BUNDLE_HASHES
)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || fail "missing $name in $ENV_FILE"
done

[[ $OUTBE_EXTERNAL_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || \
  fail 'OUTBE_EXTERNAL_IP must be an IPv4 literal'
[[ $OUTBE_CERTIFIED_RPC =~ ^https?://[^[:space:]]+$ ]] || \
  fail 'OUTBE_CERTIFIED_RPC must be an HTTP(S) URL'
[[ $OUTBE_VALIDATOR_ADDRESS =~ ^0x[0-9a-fA-F]{40}$ ]] || \
  fail 'OUTBE_VALIDATOR_ADDRESS must be a 20-byte hex address'
[[ $OUTBE_MONGODB_IMAGE =~ @sha256:[0-9a-fA-F]{64}$ ]] || \
  fail 'OUTBE_MONGODB_IMAGE must be pinned by sha256 digest'
[[ $OCOMP_CHAIN_ID =~ ^[1-9][0-9]*$ ]] || fail 'OCOMP_CHAIN_ID must be positive'
[[ $OCOMP_GENESIS_HASH =~ ^0x[0-9a-f]{64}$ ]] || \
  fail 'OCOMP_GENESIS_HASH must be a 32-byte hex value'
[[ $OCOMP_BOOT_NONCE =~ ^0x[0-9a-f]{64}$ ]] || \
  fail 'OCOMP_BOOT_NONCE must be a 32-byte hex value'
[[ $OCOMP_PROTOCOL_BUNDLE_HASHES =~ ^0x[0-9a-f]{64}$ ]] || \
  fail 'exactly one OCOMP protocol bundle hash is supported'
[[ $OUTBE_BOOTNODES == enode://* ]] || fail 'OUTBE_BOOTNODES is invalid'

IFS=, read -r -a consensus_peers <<<"$OUTBE_CONSENSUS_PEERS"
[[ ${#consensus_peers[@]} -gt 0 ]] || fail 'OUTBE_CONSENSUS_PEERS is empty'
for peer in "${consensus_peers[@]}"; do
  [[ $peer =~ ^[0-9a-fA-F]{96}@[0-9.]+:[0-9]+$ ]] || \
    fail "invalid consensus peer: $peer"
done

case $OUTBE_ENCLAVE_RUNTIME in
  system-gramine)
    command -v gramine-sgx >/dev/null || fail 'gramine-sgx is not installed'
    [[ -f $OUTBE_ROOT/outbe-tee-enclave.manifest.sgx ]] || \
      fail 'signed Gramine manifest is missing'
    [[ -f $OUTBE_ROOT/outbe-tee-enclave.sig ]] || \
      fail 'signed Gramine enclave signature is missing'
    ;;
  bundled-sgx)
    [[ -x $OUTBE_ROOT/sgx/bin/outbe-tee-enclave-launch ]] || \
      fail 'bundled SGX launcher is missing or not executable'
    for relative in \
      bin/outbe-tee-enclave \
      gramine/loader \
      gramine/libpal.so \
      network-descriptor-v1.bin \
      outbe-tee-enclave.manifest.sgx \
      outbe-tee-enclave.sig; do
      [[ -f $OUTBE_ROOT/sgx/$relative ]] || \
        fail "missing bundled SGX artifact: $relative"
    done
    ;;
  *)
    fail 'OUTBE_ENCLAVE_RUNTIME must be system-gramine or bundled-sgx'
    ;;
esac

required_files=(
  genesis.json
  reth-bootnodes.txt
  dkg_polynomial.hex
  dkg_output.hex
  protocol-bundle-v1.ocb1
  SHA256SUMS
)
required_binaries=(
  outbe-chain
  outbe-cli
  outbe-keygen
  outbe-feeder
  outbe-ocomp
  outbe-radicle
  outbe-tee-enclave
)
for name in "${required_files[@]}"; do
  [[ -f $OUTBE_ROOT/$name ]] || fail "missing bundle file: $name"
done
for name in "${required_binaries[@]}"; do
  [[ -x $OUTBE_ROOT/$name ]] || fail "missing executable: $name"
done

(
  cd "$OUTBE_ROOT"
  sha256sum -c --quiet SHA256SUMS
) || fail 'bundle checksum verification failed'

[[ $(jq -er '.config.chainId' "$OUTBE_ROOT/genesis.json") == "$OCOMP_CHAIN_ID" ]] || \
  fail 'genesis chain ID does not match validator.env'

if ! getent group outbe >/dev/null; then
  groupadd --system outbe
fi
if ! getent passwd outbe >/dev/null; then
  useradd --system --gid outbe --home-dir "$OUTBE_ROOT" \
    --shell /usr/sbin/nologin outbe
fi

for path in "$KEYS_DIR" "$VALIDATOR_ROOT" "$OUTBE_ROOT/tee"; do
  [[ ! -L $path ]] || fail "refusing symlink state path: $path"
done
[[ -d $KEYS_DIR ]] || fail "keys directory is missing: $KEYS_DIR"

install -d -o outbe -g outbe -m 0750 \
  "$VALIDATOR_ROOT" \
  "$VALIDATOR_ROOT/data" \
  "$VALIDATOR_ROOT/consensus" \
  "$VALIDATOR_ROOT/logs" \
  "$VALIDATOR_ROOT/mongodb" \
  "$OCOMP_DOMAIN" \
  "$KEYS_DIR/radicle/storage" \
  "$KEYS_DIR/radicle/node" \
  "$KEYS_DIR/radicle/cobs"
install -d -o root -g root -m 0700 "$OUTBE_ROOT/tee"

secrets=(
  signing-key.hex
  evm-key.hex
  reth-p2p-secret.hex
  ocomp-key-v1.hex
  ocomp-evm-key.hex
  radicle/keys/radicle
)
for secret in "${secrets[@]}"; do
  [[ -f $KEYS_DIR/$secret && ! -L $KEYS_DIR/$secret ]] || \
    fail "required secret is missing: $secret"
done

chown -R outbe:outbe "$KEYS_DIR"
find "$KEYS_DIR" -type d -exec chmod 0700 {} +
for secret in "${secrets[@]}"; do
  chmod 0600 "$KEYS_DIR/$secret"
done

canonical_hex_file() {
  local path=$1
  local size=$2
  local description=$3
  [[ $(stat -c %s "$path") -eq $size ]] && \
    LC_ALL=C grep -Eq '^[0-9a-f]{64}$' "$path" || \
    fail "$description is not canonical lowercase hex"
}

canonical_hex_file "$KEYS_DIR/evm-key.hex" 64 'evm-key.hex'
canonical_hex_file "$KEYS_DIR/reth-p2p-secret.hex" 64 \
  'reth-p2p-secret.hex'
canonical_hex_file "$KEYS_DIR/ocomp-key-v1.hex" 65 'ocomp-key-v1.hex'
canonical_hex_file "$KEYS_DIR/ocomp-evm-key.hex" 64 'ocomp-evm-key.hex'

"$OUTBE_ROOT/outbe-keygen" verify --key "$KEYS_DIR/signing-key.hex"

install -o outbe -g outbe -m 0600 \
  "$KEYS_DIR/ocomp-key-v1.hex" "$OCOMP_DOMAIN/ocomp-key-v1.hex"
ocomp_evm_tmp=$(mktemp)
trap 'rm -f "$ocomp_evm_tmp"' EXIT
tr -d '\n' < "$KEYS_DIR/ocomp-evm-key.hex" > "$ocomp_evm_tmp"
printf '\n' >> "$ocomp_evm_tmp"
install -o outbe -g outbe -m 0600 \
  "$ocomp_evm_tmp" "$OCOMP_DOMAIN/ocomp-evm-key.hex"

bundle_catalog=$OCOMP_DOMAIN/protocol-bundles-v1
bundle_name=${OCOMP_PROTOCOL_BUNDLE_HASHES#0x}.ocb1
install -d -o outbe -g outbe -m 0750 "$bundle_catalog"
unexpected=$(find "$bundle_catalog" -maxdepth 1 -type f ! -name "$bundle_name" -print -quit)
[[ -z $unexpected ]] || fail "unexpected OCOMP bundle in runtime catalog: $unexpected"
install -o outbe -g outbe -m 0640 \
  "$OUTBE_ROOT/protocol-bundle-v1.ocb1" "$bundle_catalog/$bundle_name"
install -o outbe -g outbe -m 0640 \
  "$OUTBE_ROOT/protocol-bundle-v1.ocb1" "$OCOMP_DOMAIN/protocol-bundle-v1.ocb1"

chown root:outbe "$ENV_FILE" "$FEEDER_CONFIG" "$STORAGE_CONFIG"
chmod 0640 "$ENV_FILE" "$FEEDER_CONFIG" "$STORAGE_CONFIG"
chown root:root "$HELPER"
chmod 0755 "$HELPER"

install -o root -g root -m 0644 \
  "$SOURCE_DIR/systemd/"*.service \
  "$SOURCE_DIR/systemd/"*.target \
  "$SOURCE_DIR/systemd/"*.timer \
  /etc/systemd/system/

systemctl daemon-reload

printf '%s\n' 'Outbe validator services installed but not started.'
