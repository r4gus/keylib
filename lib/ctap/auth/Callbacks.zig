//! Callbacks provided by the underlying platform/ the user
//!
//! The callbacks are required to keep the library platform
//! agnostic.

const std = @import("std");

pub const LoadError = error{
    DoesNotExist,
    NotEnoughMemory,
};

/// Fill the given buffer with (cryptographically secure) random bytes
rand: *const fn (b: []u8) void,

/// Get the time in ms since boot
millis: *const fn () u64,

/// Load CBOR encoded settings
///
/// This operation should fail with `DoesNotExist` if there are no settings
/// stored.
load_settings: *const fn (a: std.mem.Allocator) LoadError![]const u8,

/// Store CBOR encoded settings
store_settings: *const fn (d: []const u8) void,

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
