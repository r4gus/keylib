const std = @import("std");
const fido = @import("../../../main.zig");
const cbor = @import("zbor");
const SigAlg = fido.ctap.crypto.SigAlg;
const EcdsaP256Sha256 = @import("../ecdsa.zig").EcdsaP256Sha256;
const dt = fido.common.dt;

pub const Es256 = SigAlg{
    .alg = .Es256,
    .create = create,
    .create_det = create_det,
    .sign = sign,
    .from_priv = from_priv,
};

pub fn create(rand: std.Random) ?cbor.cose.Key {
    // Create key pair
    var seed: [32]u8 = undefined;
    rand.bytes(&seed);
    return create_det(&seed);
}

pub fn create_det(seed: []const u8) ?cbor.cose.Key {
    const kp = EcdsaP256Sha256.KeyPair.create(seed[0..32].*) catch return null;
    return cbor.cose.Key.fromP256PrivPub(.Es256, kp.secret_key, kp.public_key);
}

pub fn sign(
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    out: []u8,
) ?[]const u8 {
    if (raw_private_key.len != 32) return null;

    var kp = EcdsaP256Sha256.KeyPair.fromSecretKey(
        try EcdsaP256Sha256.SecretKey.fromBytes(raw_private_key[0..32].*),
    ) catch return null;
    var signer = try kp.signer(null);

    // Append data that should be signed together
    for (data_seq) |data| {
        signer.update(data);
    }

    // Sign the data
    const sig = signer.finalize() catch return null;
    var buffer: [EcdsaP256Sha256.Signature.der_encoded_max_length]u8 = undefined;
    const der = sig.toDer(&buffer);

    if (out.len < der.len) return null;
    @memcpy(out[0..der.len], der);
    return out[0..der.len];
}

pub fn from_priv(priv: []const u8) ?cbor.cose.Key {
    if (priv.len != 32) return null;

    var kp = EcdsaP256Sha256.KeyPair.fromSecretKey(
        try EcdsaP256Sha256.SecretKey.fromBytes(priv[0..32].*),
    ) catch return null;

    const sec1 = kp.public_key.toUncompressedSec1();
    const pubk = cbor.cose.Key{ .P256 = .{
        .alg = .Es256,
        .x = sec1[1..33].*,
        .y = sec1[33..65].*,
    } };

    return pubk;
}
