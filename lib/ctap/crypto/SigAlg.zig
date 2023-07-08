const std = @import("std");
const cbor = @import("zbor");
const Allocator = std.mem.Allocator;

pub const KeyPair = struct {
    /// Public key encoded in CBOR COSE format (without private key!)
    cose_public_key: []const u8,
    /// The private key
    raw_private_key: []const u8,
};

/// The algorithm used
alg: cbor.cose.Algorithm,
/// Create a new random key-pair
create: *const fn (rand: std.rand.Random, allocator: Allocator) ?KeyPair,
/// Deterministically creates a new key-pair using the given seed
create_det: *const fn (seed: []const u8, allocator: std.mem.Allocator) ?KeyPair,
/// Sign the given data
sign: *const fn (
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    allocator: Allocator,
) ?[]const u8,
