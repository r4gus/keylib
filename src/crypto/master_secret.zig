const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Stored by the authenticator and used to derive all other secrets
pub const MasterSecret = [Hkdf.mac_length]u8;

/// Create a new, random master secret
pub fn create_master_secret(comptime rand: fn ([]u8) void) MasterSecret {
    var ikm: [32]u8 = undefined;
    var salt: [16]u8 = undefined;
    rand(ikm[0..]);
    rand(salt[0..]);
    return Hkdf.extract(&salt, &ikm);
}
