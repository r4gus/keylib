const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aes256Ocb = std.crypto.aead.aes_ocb.Aes256Ocb;

pub const MS_LEN = Hkdf.prk_length;
/// Stored by the authenticator and used to derive all other secrets
pub const MasterSecret = [MS_LEN]u8;

/// Create a new, random master secret using a hash based key derivation function
pub fn createMasterSecret(rand: std.rand.Random) MasterSecret {
    var ikm: [32]u8 = undefined;
    var salt: [16]u8 = undefined;
    rand.bytes(ikm[0..]);
    rand.bytes(salt[0..]);
    return Hkdf.extract(&salt, &ikm);
}

/// Derive a deterministic sub-key for message authentication codes.
pub fn deriveMacKey(ms: MasterSecret) [Hmac.mac_length]u8 {
    var mac_key: [Hmac.mac_length]u8 = undefined;
    Hkdf.expand(mac_key[0..], "MAC", ms);
    return mac_key;
}

pub fn deriveEncKey(ms: MasterSecret) [Aes256Ocb.key_length]u8 {
    var enc_key: [Aes256Ocb.key_length]u8 = undefined;
    Hkdf.expand(enc_key[0..], "ENC", ms);
    return enc_key;
}
