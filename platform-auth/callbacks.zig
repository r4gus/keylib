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

var pinHash: ?[32]u8 = null;

pub fn loadCurrentStoredPIN() LoadError![32]u8 {
    if (pinHash) |ph| {
        return ph;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storeCurrentStoredPIN(d: [32]u8) void {
    pinHash = d;
    std.debug.print("new pin hash: {x}\n", .{std.fmt.fmtSliceHexUpper(&pinHash.?)});
}

var l: ?u8 = null;

pub fn loadPINCodePointLength() LoadError!u8 {
    if (l) |len| {
        return len;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storePINCodePointLength(d: u8) void {
    l = d;
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
    std.debug.print("id: {x}, data: {x}\n", .{
        std.fmt.fmtSliceHexUpper(id),
        std.fmt.fmtSliceHexUpper(d),
    });
}
