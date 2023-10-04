const std = @import("std");
const fido = @import("../../../main.zig");
const cbor = @import("zbor");
const SigAlg = fido.ctap.crypto.SigAlg;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Es256 = SigAlg{
    .alg = .Es256,
    .create = create,
    .create_det = create_det,
    .sign = sign,
    .from_priv = from_priv,
};

pub fn create(rand: std.rand.Random, allocator: std.mem.Allocator) ?SigAlg.KeyPair {
    // Create key pair
    var seed: [32]u8 = undefined;
    rand.bytes(&seed);
    return create_det(&seed, allocator);
}

pub fn create_det(seed: []const u8, allocator: std.mem.Allocator) ?SigAlg.KeyPair {
    const kp = EcdsaP256Sha256.KeyPair.create(seed[0..32].*) catch return null;
    const sec1 = kp.public_key.toUncompressedSec1();
    const pk = kp.secret_key.toBytes();
    const pubk = cbor.cose.Key{ .P256 = .{
        .alg = .Es256,
        .x = sec1[1..33].*,
        .y = sec1[33..65].*,
    } };

    // Serialize
    var priv = allocator.alloc(u8, pk[0..].len) catch return null;
    @memcpy(priv, pk[0..]);

    var serialized_cred = std.ArrayList(u8).init(allocator);
    cbor.stringify(&pubk, .{ .enum_as_text = false }, serialized_cred.writer()) catch {
        allocator.free(priv);
        serialized_cred.deinit();
        return null;
    };

    const pubkey = serialized_cred.toOwnedSlice() catch {
        allocator.free(priv);
        serialized_cred.deinit();
        return null;
    };

    return .{
        .cose_public_key = pubkey,
        .raw_private_key = priv,
    };
}

pub fn sign(
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    allocator: std.mem.Allocator,
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
    var mem = allocator.alloc(u8, der.len) catch return null;
    @memcpy(mem, der);
    return mem;
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
