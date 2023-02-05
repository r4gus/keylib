const std = @import("std");
const cbor = @import("zbor");
const cose = cbor.cose;

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ecdsa = @import("crypto/ecdsa.zig"); // copy from std lib without automatic call to rng.
pub const ecdh = @import("crypto/ecdh.zig");

// #########################################################################################
// Credentials
// #########################################################################################

/// Length of the first half of the credential id, used in combination with the ms
/// to derive the credential.
pub const ctx_len: usize = 32;

/// The length of the mac.
pub const mac_len = Hmac.mac_length;

/// Size of the credId in bytes.
pub const cred_id_len = ctx_len + mac_len;

/// The credential id is a (random) by string used to identify a credential.
/// The credId is actually the combination of a context and a mac (CTX || MAC).
/// The CTX is used to derive the actual credential and the MAC is used to verify
/// the integrity and authenticity of the CTX.
pub const CredentialId = [cred_id_len]u8;

/// Derive a deterministic sub-key for message authentication codes.
pub fn deriveMacKey(master_secret: [mac_len]u8) [mac_len]u8 {
    var mac_key: [mac_len]u8 = undefined;
    Hkdf.expand(mac_key[0..], "MACKEY", master_secret);
    return mac_key;
}

/// Create a credential id from a context and a relying party id using a master secret.
/// rpId = CTX || HMAC(CTX || RPID)
pub fn makeCredId(ms: [mac_len]u8, ctx: []const u8, rp_id: []const u8) CredentialId {
    var cred_id: CredentialId = undefined;

    std.mem.copy(u8, cred_id[0..ctx_len], ctx);
    const key = deriveMacKey(ms);
    var m = Hmac.init(&key);
    m.update(ctx);
    m.update(rp_id);
    m.final(cred_id[ctx_len..]);

    return cred_id;
}

/// Verify the given credential id.
pub fn verifyCredId(ms: [mac_len]u8, credId: []const u8, rp_id: []const u8) bool {
    var mac: [mac_len]u8 = undefined;

    const key = deriveMacKey(ms);
    var m = Hmac.init(&key);
    m.update(credId[0..ctx_len]);
    m.update(rp_id);
    m.final(mac[0..]);

    // Calculated mac must match received mac
    return std.mem.eql(u8, credId[ctx_len..], mac[0..]);
}

/// Create a new random context.
pub fn newContext(comptime rand: fn ([]u8) void) [ctx_len]u8 {
    var ctx: [ctx_len]u8 = undefined;
    rand(ctx[0..]);
    return ctx;
}

// #########################################################################################
// Signatures
// #########################################################################################

pub const Es256 = ecdsa.EcdsaP256Sha256;
pub const KeyPair = Es256.KeyPair;
pub const Signature = Es256.Signature;
pub const der_len = Es256.Signature.der_encoded_max_length;

/// Check if the given COSE algorithm is supported.
pub fn isValidAlgorithm(alg: cbor.cose.Algorithm) bool {
    return switch (alg) {
        .Es256 => true,
        else => false,
    };
}

/// Derive a (deterministic) key-pair from a given context `ctx`.
///
/// Note: If you change the master secret used during `createKeyPair`
/// you won't be able to derive the correct key-pair from the given context.
pub fn deriveKeyPair(master_secret: [mac_len]u8, ctx: [ctx_len]u8) !KeyPair {
    var seed: [mac_len]u8 = undefined;
    Hkdf.expand(seed[0..], ctx[0..], master_secret);
    return try KeyPair.create(seed);
}

pub fn sign(kp: KeyPair, auth_data: []const u8, client_data_hash: []const u8) !Signature {
    var st = try kp.signer(null);
    st.update(auth_data);
    st.update(client_data_hash);
    return st.finalize();
}

pub fn getCoseKey(kp: KeyPair) cose.Key {
    return cose.Key.fromP256Pub(.Es256, kp.public_key);
}

// #########################################################################################
// State
// #########################################################################################

pub fn createMasterSecret(comptime rand: fn ([]u8) void) [32]u8 {
    var ikm: [32]u8 = undefined;
    var salt: [16]u8 = undefined;
    rand(ikm[0..]);
    rand(salt[0..]);
    return Hkdf.extract(&salt, &ikm);
}

pub fn pinHash(pin: []const u8) [16]u8 {
    var ph: [32]u8 = undefined;
    Sha256.hash(pin, &ph, .{});
    return ph[0..16].*;
}

pub fn defaultPinHash() [16]u8 {
    return pinHash("candystick");
}

test "crypto test" {
    _ = ecdh;
}
