const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const cose = @import("zbor").cose;

pub const EcdsaP256Sha256 = @import("ecdsa.zig").EcdsaP256Sha256;

pub const MasterSecret = @import("master_secret.zig").MasterSecret;

const context = @import("context.zig");
pub const Context = context.Context;

pub const Algorithm = enum(i32) {
    Es256,
};

pub const SignatureAlgorithmKeyPair = union(Algorithm) {
    Es256: struct {
        kp: EcdsaP256Sha256.KeyPair,
        der: [EcdsaP256Sha256.Signature.der_encoded_max_length]u8 = undefined,
    },

    /// Derive a (deterministic) key-pair from a given context `ctx`.
    ///
    /// The context determines the algorithm the key pair is created for.
    ///
    /// The creation of the key pair should only fail during makeCredential, i.e.,
    /// it's safe to use `catch unreachable` in all other cases.
    pub fn new(ms: MasterSecret, ctx: Context) !@This() {
        const alg = context.alg_from_context(ctx);
        var seed: [Hkdf.prk_length]u8 = undefined;
        Hkdf.expand(seed[0..], ctx[0..], ms);

        return switch (alg) {
            .Es256 => .{ .Es256 = .{
                .kp = try EcdsaP256Sha256.KeyPair.create(seed),
            } },
            else => error.UnsupportedAlgorithm,
        };
    }

    /// Sign the given data using the private part of the key pair.
    pub fn sign(self: *@This(), auth_data: []const u8, client_data_hash: []const u8) []const u8 {
        switch (self.*) {
            Algorithm.Es256 => |*es256| {
                var st = es256.kp.signer(null) catch unreachable;
                st.update(auth_data);
                st.update(client_data_hash);
                const sig = st.finalize() catch unreachable;
                return sig.toDer(&es256.der);
            },
        }
    }

    pub fn algorithm(self: *const @This()) cose.Algorithm {
        return switch (self.*) {
            Algorithm.Es256 => cose.Algorithm.Es256,
        };
    }

    /// Turn the given key pair into a COSE key, ready for serialization.
    pub fn to_cose(self: *const @This()) cose.Key {
        return switch (self.*) {
            Algorithm.Es256 => |*es256| cose.Key.fromP256Pub(.Es256, es256.kp.public_key),
        };
    }
};
