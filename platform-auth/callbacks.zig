const std = @import("std");
const fido = @import("fido");

const LoadError = fido.ctap.authenticator.Callbacks.LoadError;

/// Fill the given buffer with (cryptographically secure) random bytes
pub fn rand(b: []u8) void {
    std.crypto.random.bytes(b);
}

/// Get the epoch time in ms
pub fn millis() u64 {
    return @intCast(u64, std.time.milliTimestamp());
}

pub fn load_settings(a: std.mem.Allocator) LoadError![]const u8 {
    _ = a;
    return "";
}

pub fn store_settings(d: []const u8) void {
    _ = d;
}

pub fn load_credential_by_id(id: []const u8, a: std.mem.Allocator) LoadError![]const u8 {
    _ = id;
    _ = a;
    return "";
}

pub fn store_credential_by_id(id: []const u8, d: []const u8) void {
    _ = id;
    _ = d;
}
