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

pub fn up(user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) bool {
    _ = user;
    _ = rp;
    return true;
}

var pinHash: [32]u8 = "\x9f\x86\xd0\x81\x88\x4c\x7d\x65\x9a\x2f\xea\xa0\xc5\x5a\xd0\x15\xa3\xbf\x4f\x1b\x2b\x0b\x82\x2c\xd1\x5d\x6c\x15\xb0\xf0\x0a\x08".*;

pub fn load_pin_hash() LoadError![32]u8 {
    return pinHash;
}

pub fn store_pin_hash(d: [32]u8) void {
    pinHash = d;
    std.debug.print("new pin hash: {x}\n", .{std.fmt.fmtSliceHexUpper(&pinHash)});
}

var retries: u8 = 8;

pub fn get_retries() LoadError!u8 {
    return retries;
}

pub fn set_retries(r: u8) void {
    retries = r;
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
