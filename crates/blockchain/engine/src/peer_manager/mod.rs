mod admission;
pub(crate) mod actor;
pub(crate) mod ingress;

pub(crate) use actor::{Actor, Config};
pub(crate) use ingress::Mailbox;
