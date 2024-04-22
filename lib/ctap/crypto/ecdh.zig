const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

pub const EcdhP256 = Ecdh(crypto.ecc.P256);

pub fn Ecdh(comptime Curve: type) type {
    return struct {
        pub const secret_length = Curve.scalar.encoded_length;
        pub const public_length = Curve.Fe.encoded_length;

        pub const KeyPair = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a uncompressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            /// The public key is the product `eG` of a generator `G` and a private key `e`.
            public_key: Curve,
            /// A secret scalar e.
            secret_key: [secret_length]u8,

            /// Create a new key pair using a RANDOMLY generated seed.
            pub fn create(seed: [secret_length]u8) !KeyPair {
                var kp: KeyPair = undefined;
                @memcpy(&kp.secret_key, &seed);
                kp.public_key = try recoverPublicKey(kp.secret_key);
                return kp;
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(kp: KeyPair) [compressed_sec1_encoded_length]u8 {
                return kp.public_key.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(kp: KeyPair) [uncompressed_sec1_encoded_length]u8 {
                return kp.public_key.toUncompressedSec1();
            }
        };

        /// Compute the public key for a given private key.
        pub fn recoverPublicKey(secret_key: [secret_length]u8) IdentityElementError!Curve {
            return try Curve.basePoint.mul(secret_key, .little);
        }

        pub fn scalarmultXY(secret_key: [secret_length]u8, pub_x: [public_length]u8, pub_y: [public_length]u8) !Curve {
            const x = try Curve.Fe.fromBytes(pub_x[0..].*, .big);
            const y = try Curve.Fe.fromBytes(pub_y[0..].*, .big);
            const c = try Curve.fromAffineCoordinates(.{ .x = x, .y = y });
            const secret = try c.mul(secret_key, .little);
            return secret;
        }
    };
}

const TestVector = struct {
    seed_1: []const u8, // little endian
    sec1_pub_1: []const u8, // big endian
    seed_2: []const u8, // little endian
    sec1_pub_2: []const u8, // big endian
    shared: []const u8,
};

// 1 ------------------------------------------------------------------------------
// k: 2950161782655570540676804833206013362761296170713583524683291525408100401277
// x: 72012666485689920686349371229719520079129025318776017657777002731415147050435
// y: 82774346030720574195738104733363612151633888318189006270161920746901497752063
// 2 ------------------------------------------------------------------------------
// k: 40798969142379699069411319556357690403406277790329503364538485924349264581035
// x: 35880122959583058435597142902132466821046587199372209813642092314971621865447
// y: 97019214247574472146350611690487571862063450007374962849005135920536613627823
// 1*2 ----------------------------------------------------------------------------
// x: 74480588571804104165548909343629343101087858447149553902224553189006333009730
// y: 17514364307054875620496156261313566698070339587494778530888946462521182668340

test "ecdh: generate key" {
    const vectors = [_]TestVector{
        .{ .seed_1 = "\x7d\x40\x1f\xff\x9d\x6e\x6a\x6d\xcf\xb6\xa4\xbe\x8d\x2a\xc7\x6b\xe6\xb4\x52\xaf\xb5\x0e\xdb\x50\xa5\x4f\x28\x4c\x7e\xbb\x85\x06", .sec1_pub_1 = "\x04\x9f\x35\xb9\x8e\x8f\xac\xc2\xe3\x0f\x81\xab\xe2\x89\x46\x97\x4f\x6d\xe6\xb6\x3f\x3d\x53\xed\xd7\xa6\x61\x4e\x38\xfd\xb6\xf5\xc3\xb7\x00\x9e\x9e\x29\xab\xc0\x9e\x62\x96\xa8\x14\x3a\x75\x00\x54\x69\x57\xbb\x75\x85\xb8\xfd\xdb\xc1\x27\x66\x5f\x58\x74\xa9\xff", .seed_2 = "\xab\xd1\x48\x54\x46\xa3\x23\xd3\xd0\xa1\x24\x3d\xc3\x44\xd1\xf6\x36\xd3\xb4\x56\xb4\xd0\xac\x24\xf0\x46\xa1\xd8\xf0\x65\x33\x5a", .sec1_pub_2 = "\x04\x4f\x53\x6e\x0f\xb0\xe9\x99\xa7\x3f\x0e\x3d\x02\xae\x59\x2b\xd2\xe5\x7f\x77\xfd\xbd\x41\xa2\x8b\x12\x65\xe0\xcf\x5e\xe0\xb7\xe7\xd6\x7e\xed\xe6\x38\x3a\x49\x36\xe8\xb4\x3c\x38\xd8\xbe\x96\xdb\x4a\x1f\x9a\x15\xbd\x81\x22\xb0\x3e\x0b\x0c\x99\x4e\x1d\x27\xaf", .shared = "\x04\xa4\xaa\x84\xec\x5f\xa1\x01\x49\x5a\x37\x1a\x3b\x1a\xf7\x75\xe2\xb1\x5b\x36\xb2\xda\xff\x25\x73\x07\xc2\x1e\x16\xd8\x61\x5f\x42\x26\xb8\xc7\x66\x21\x8e\x93\xf1\xbb\x0a\x90\xa5\x31\x48\x41\xab\x31\x8f\xb2\x03\x35\x6c\xca\x1a\x85\xd5\x6a\xeb\x44\x70\x46\x34" },
    };

    for (vectors) |vector| {
        const kp = try EcdhP256.KeyPair.create(vector.seed_1[0..32].*);
        try std.testing.expectEqualSlices(u8, vector.sec1_pub_1, &kp.toUncompressedSec1());

        const kp2 = try EcdhP256.KeyPair.create(vector.seed_2[0..32].*);
        try std.testing.expectEqualSlices(u8, vector.sec1_pub_2, &kp2.toUncompressedSec1());

        const s1 = try EcdhP256.scalarmultXY(kp.secret_key, vector.sec1_pub_2[1..33].*, vector.sec1_pub_2[33..65].*);
        try std.testing.expectEqualSlices(u8, vector.shared, &s1.toUncompressedSec1());
    }
}
