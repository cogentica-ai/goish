// os/user — module root.
//
// Split the way Go splits it: `user.rs` for the value types and their
// errors, `lookup.rs` for the public lookups, `lookup_unix.rs` for the
// /etc/passwd and /etc/group readers. This file re-exports, so callers
// keep writing `user::Current()` and `user::Lookup(name)`.

mod lookup;
mod lookup_unix;
mod user;

pub use lookup::{Current, Lookup, LookupGroup, LookupGroupId, LookupId};
pub use user::{
    Group, UnknownGroupError, UnknownGroupIdError, UnknownUserError, UnknownUserIdError, User,
};
