//! Callbacks provided by the underlying platform/ the user
//!
//! The callbacks are required to keep the library platform
//! agnostic.

const std = @import("std");
const fido = @import("../../main.zig");
const cks = @import("cks");

pub const LoadError = error{
    DoesNotExist,
    NotEnoughMemory,
};

pub const StoreError = error{
    KeyStoreFull,
};

/// Result value of the `up` callback
pub const UpResult = enum {
    /// The user has denied the action
    Denied,
    /// The user has accepted the action
    Accepted,
    /// The user presence check has timed out
    Timeout,
};

pub const UpReason = enum {
    MakeCredential,
    GetAssertion,
    AuthenticatorSelection,
    Reset,
};

/// Interface for a thread local CSPRNG
rand: std.rand.Random,

/// Get the time in ms since boot
millis: *const fn () i64,

/// Request user presence
up: *const fn (reason: UpReason, user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) UpResult,

/// User verification callback
///
/// This callback should execute a built-in user verification method.
///
/// This callback is optional. Client request with the uv flag set will
/// fail if this callback isn't provided.
///
/// Possible methods are:
/// - Password
/// - Finger print sensor
/// - Pattern
uv: ?*const fn () bool = null,

createEntry: *const fn (id: []const u8) cks.Error!cks.Entry,
getEntry: *const fn (id: []const u8) ?*cks.Entry,
getEntries: *const fn () ?[]cks.Entry,
addEntry: *const fn (entry: cks.Entry) cks.Error!void,
removeEntry: *const fn (id: []const u8) cks.Error!void,
persist: *const fn () error{Fatal}!void,

//// Called on a reset
////
//// This callback should reset the authenticator back to the factory default state, including:
////
//// - Invalidates all generated credentials, including those created over CTAP1/U2F
//// - Erases all discoverable credentials
//// - Resets the serialized large-blob array storage, if any, to the initial serialized large-blob array value
//// - Disables those features that are denoted as being subject to disablement by authenticatorReset
//// - Resets those features that are denoted as being subject to reset by authenticatorReset
reset: *const fn () void,

// +++++++++++++++++++++++++++++++++++++++
// Optional
// +++++++++++++++++++++++++++++++++++++++

/// Callback to add additionla constraints to a PIN.
///
/// Those constraints are checked when settings and changing a PIN. Returns true
/// if all constraints are met, false otherwise.
validate_pin_constraints: ?*const fn (pin: []const u8) bool = null,
