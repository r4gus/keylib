//! Callbacks provided by the underlying platform/ the user
//!
//! The callbacks are required to keep the library platform
//! agnostic.

const std = @import("std");
const fido = @import("../../main.zig");

pub const LoadError = error{
    DoesNotExist,
    NotEnoughMemory,
};

/// Fill the given buffer with (cryptographically secure) random bytes
rand: *const fn (b: []u8) void,

/// Get the time in ms since boot
millis: *const fn () u64,

/// Request user presence
up: *const fn (user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) bool,

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

/// Load the full sha256 pin hash
///
/// This operation should fail with `DoesNotExist` if there are no settings
/// stored.
loadCurrentStoredPIN: *const fn () LoadError![32]u8,

/// Store the full sha256 pin hash
storeCurrentStoredPIN: *const fn (d: [32]u8) void,

/// Load the code point length of the password corresponding to the stored pin hash
loadPINCodePointLength: *const fn () LoadError!u8,

/// Store the code point length of the password corresponding to the stored pin hash
storePINCodePointLength: *const fn (d: u8) void,

get_retries: *const fn () LoadError!u8,
set_retries: *const fn (r: u8) void,

/// Load a CBOR encoded credential using the given id
///
/// This operation should fail with `DoesNotExist` if there is no credential
/// with the given id.
load_credential_by_id: *const fn (id: []const u8, a: std.mem.Allocator) LoadError![]const u8,

/// Store a CBOR encoded credential using the given id
///
/// This should overwrite any existing credential with the same id
store_credential_by_id: *const fn (id: []const u8, d: []const u8) void,

/// Load a CBOR encoded credential using the given rpId
///
/// This callback is optional for discoverable credentials.
///
/// This operation should fail with `DoesNotExist` if there is no credential
/// with the given id.
load_credential_by_rpid: ?*const fn (rpid: []const u8, a: std.mem.Allocator) LoadError![]const u8 = null,

/// Store a CBOR encoded credential using the given rpId
///
/// This callback is optional for discoverable credentials.
///
/// Any existing credential bound to the same rpId should be overwritten.
store_credential_by_rpid: ?*const fn (rpid: []const u8, d: []const u8) void = null,
