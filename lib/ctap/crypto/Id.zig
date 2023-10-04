const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const MasterSecret = fido.ctap.crypto.master_secret.MasterSecret;
const CredentialCreationPolicy = fido.ctap.extensions.CredentialCreationPolicy;

pub const CTX_LEN = 32;
pub const ID_LEN = CTX_LEN + Hmac.mac_length;

raw: [ID_LEN]u8,

pub fn new(
    alg: cbor.cose.Algorithm,
    policy: CredentialCreationPolicy,
    ms: MasterSecret,
    rpid: []const u8,
    rand: std.rand.Random,
) @This() {
    var id = @This(){ .raw = undefined };

    // Encode signature algorithm bound to this id
    @memcpy(id.raw[0..4], alg.to_raw()[0..4]);

    // Encode credential creation policy
    id.raw[4] = @intFromEnum(policy);

    // Create a 28 byte random context
    rand.bytes(id.raw[5..32]);

    // Bind rpid to the credential using a MAC
    const mk = deriveMacKey(ms);
    var m = Hmac.init(&mk);
    m.update(id.raw[0..32]); // The context
    m.update(rpid);
    m.final(id.raw[32..]);

    // Return `ALG || POL || CTX || MAC(ALG || POL || CTX || rpId)`
    return id;
}

pub fn from_raw(
    raw: []const u8,
    ms: MasterSecret,
    rpid: []const u8,
) !@This() {
    // Verify length
    if (raw.len != ID_LEN) {
        return error.InvalidIdLength;
    }

    // Verify MAC
    var mac: [Hmac.mac_length]u8 = undefined;
    const mk = deriveMacKey(ms);
    var m = Hmac.init(&mk);
    m.update(raw[0..32]);
    m.update(rpid);
    m.final(mac[0..]);

    if (!std.mem.eql(u8, raw[CTX_LEN..], mac[0..])) {
        return error.InvalidMac;
    }

    return @This(){ .raw = raw[0..ID_LEN].* };
}

pub fn getAlg(self: *const @This()) cbor.cose.Algorithm {
    return cbor.cose.Algorithm.from_raw(self.raw[0..4].*);
}

pub fn getPolicy(self: *const @This()) CredentialCreationPolicy {
    const pol: CredentialCreationPolicy = @enumFromInt(self.raw[4]);
    return pol;
}

pub fn deriveSeed(self: *const @This(), ms: MasterSecret) [32]u8 {
    var seed: [32]u8 = undefined;
    Hkdf.expand(seed[0..], self.raw[0..CTX_LEN], ms);
    return seed;
}

/// Derive a deterministic sub-key for message authentication codes.
fn deriveMacKey(ms: MasterSecret) [Hmac.mac_length]u8 {
    var mac_key: [Hmac.mac_length]u8 = undefined;
    Hkdf.expand(mac_key[0..], "MACKEY", ms);
    return mac_key;
}
