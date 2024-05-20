const std = @import("std");
const cbor = @import("zbor");
const Allocator = std.mem.Allocator;
const fido = @import("../../main.zig");
const dt = fido.common.dt;

pub const KeyPair = struct {
    /// Public key encoded in CBOR COSE format (without private key!)
    ///
    /// TODO: adujst the key size!!!
    cose_public_key: dt.ABS512B,
    /// The private key
    ///
    /// TODO: adujst the key size!!!
    raw_private_key: dt.ABS256B,
};

/// The algorithm used
alg: cbor.cose.Algorithm,
/// Create a new random key-pair
create: *const fn (rand: std.rand.Random) ?KeyPair,
/// Deterministically creates a new key-pair using the given seed
create_det: *const fn (seed: []const u8) ?KeyPair,
/// Sign the given data
sign: *const fn (
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    out: []u8,
) ?[]const u8,
from_priv: *const fn (priv: []const u8) ?cbor.cose.Key,
