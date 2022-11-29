// https://www.rfc-editor.org/rfc/rfc9053.html#section-6.3.1

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;

pub const EcdhP256Hkdfsha256 = Ecdh(crypto.ecc.P256, crypto.kdf.hkdf.Hkdfsha256);

pub fn Ecdh(comptime Curve: type, comptime Kdf: type) type {
    _ = Kdf;

    return struct {
        pub const SecretKey = struct {
            pub const encoded_length = Curve.scalar.encoded_length;

            bytes: Curve.scalar.CompressedScalar,

            pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
                return SecretKey{ .bytes = bytes };
            }

            pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
                return sk.bytes;
            }
        };

        pub const PublicKey = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            p: Curve,

            /// Create a public key from a SEC-1 representation.
            pub fn fromSec1(sec1: []const u8) !PublicKey {
                return PublicKey{ .p = try Curve.fromSec1(sec1) };
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };
    };
}
