// This is a copy of the std lib file found at https://github.com/ziglang/zig/blob/master/lib/std/crypto/25519/x25519.zig.
// The difference is that `create()` doesn't use the crypto rng, i.e. it can
// be used in environments where a default rng is not available through std.
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;

const Sha512 = crypto.hash.sha2.Sha512;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

/// X25519 DH function.
pub const X25519 = struct {
    /// The underlying elliptic curve.
    pub const Curve = std.crypto.ecc.Curve25519;
    /// Length (in bytes) of a secret key.
    pub const secret_length = 32;
    /// Length (in bytes) of a public key.
    pub const public_length = 32;
    /// Length (in bytes) of the output of the DH function.
    pub const shared_length = 32;
    /// Seed (for key pair creation) length in bytes.
    pub const seed_length = 32;

    /// An X25519 key pair.
    pub const KeyPair = struct {
        /// Public part.
        public_key: [public_length]u8,
        /// Secret part.
        secret_key: [secret_length]u8,

        /// Create a new key pair using an optional seed.
        pub fn create(seed: [seed_length]u8) IdentityElementError!KeyPair {
            var kp: KeyPair = undefined;
            mem.copy(u8, &kp.secret_key, seed[0..]);
            kp.public_key = try X25519.recoverPublicKey(seed);
            return kp;
        }

        /// Create a key pair from an Ed25519 key pair
        pub fn fromEd25519(ed25519_key_pair: crypto.sign.Ed25519.KeyPair) (IdentityElementError || EncodingError)!KeyPair {
            const seed = ed25519_key_pair.secret_key.seed();
            var az: [Sha512.digest_length]u8 = undefined;
            Sha512.hash(&seed, &az, .{});
            var sk = az[0..32].*;
            Curve.scalar.clamp(&sk);
            const pk = try publicKeyFromEd25519(ed25519_key_pair.public_key);
            return KeyPair{
                .public_key = pk,
                .secret_key = sk,
            };
        }
    };

    /// Compute the public key for a given private key.
    pub fn recoverPublicKey(secret_key: [secret_length]u8) IdentityElementError![public_length]u8 {
        const q = try Curve.basePoint.clampedMul(secret_key);
        return q.toBytes();
    }

    /// Compute the X25519 equivalent to an Ed25519 public eky.
    pub fn publicKeyFromEd25519(ed25519_public_key: crypto.sign.Ed25519.PublicKey) (IdentityElementError || EncodingError)![public_length]u8 {
        const pk_ed = try crypto.ecc.Edwards25519.fromBytes(ed25519_public_key.bytes);
        const pk = try Curve.fromEdwards25519(pk_ed);
        return pk.toBytes();
    }

    /// Compute the scalar product of a public key and a secret scalar.
    /// Note that the output should not be used as a shared secret without
    /// hashing it first.
    pub fn scalarmult(secret_key: [secret_length]u8, public_key: [public_length]u8) IdentityElementError![shared_length]u8 {
        const q = try Curve.fromBytes(public_key).clampedMul(secret_key);
        return q.toBytes();
    }
};
