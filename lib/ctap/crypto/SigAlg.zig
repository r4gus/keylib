const std = @import("std");
const cbor = @import("zbor");
const Allocator = std.mem.Allocator;
const fido = @import("../../main.zig");
const dt = fido.common.dt;

/// The algorithm used
alg: cbor.cose.Algorithm,
/// Create a new random key-pair
create: *const fn (rand: std.rand.Random) ?cbor.cose.Key,
/// Deterministically creates a new key-pair using the given seed
create_det: *const fn (seed: []const u8) ?cbor.cose.Key,
/// Sign the given data
sign: *const fn (
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    out: []u8,
) ?[]const u8,
from_priv: *const fn (priv: []const u8) ?cbor.cose.Key,
