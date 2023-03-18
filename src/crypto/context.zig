const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const cose = @import("zbor").cose;

const MasterSecret = @import("master_secret.zig").MasterSecret;

pub const context_len = 32;
pub const cred_id_len = context_len + Hmac.mac_length;

/// The context is part of the credential id and used
/// to derive a key pair (in conjunction with the master secret).
pub const Context = [context_len]u8;

/// /// The credential id is a (random) by string used to identify a credential.
/// The credId is actually the combination of a context and a mac (CTX || MAC).
/// The CTX is used to derive the actual credential and the MAC is used to verify
/// the integrity and authenticity of the CTX.
pub const CredId = [cred_id_len]u8;

/// Create a new random context.
///
/// The context consists of a (4 byte) COSE algorithm identifier followed
/// by 28 random bytes.
pub fn newContext(rand: *const fn ([]u8) void, alg: cose.Algorithm) Context {
    var ctx: Context = undefined;
    // The first four bytes encode the algorithm
    std.mem.copy(u8, ctx[0..4], alg.to_raw()[0..]);
    rand(ctx[4..]);
    return ctx;
}

/// Get the COSE algorithm encoded in the given context.
pub fn alg_from_context(ctx: Context) cose.Algorithm {
    return cose.Algorithm.from_raw(ctx[0..4].*);
}

/// Derive a deterministic sub-key for message authentication codes.
pub fn derive_mac_key(ms: MasterSecret) [Hmac.mac_length]u8 {
    var mac_key: [Hmac.mac_length]u8 = undefined;
    Hkdf.expand(mac_key[0..], "MACKEY", ms);
    return mac_key;
}

/// Create a credential id from a context and a relying party id using a master secret.
/// rpId = CTX || HMAC(CTX || RPID)
pub fn make_cred_id(ms: MasterSecret, ctx: Context, rp_id: []const u8) CredId {
    var cred_id: CredId = undefined;

    std.mem.copy(u8, cred_id[0..context_len], ctx[0..]);
    const key = derive_mac_key(ms);
    var m = Hmac.init(&key);
    m.update(&ctx);
    m.update(rp_id);
    m.final(cred_id[context_len..]);

    return cred_id;
}

/// Verify the given credential id.
pub fn verify_cred_id(ms: MasterSecret, cred_id: CredId, rp_id: []const u8) bool {
    var mac: [Hmac.mac_length]u8 = undefined;

    const key = derive_mac_key(ms);
    var m = Hmac.init(&key);
    m.update(cred_id[0..context_len]);
    m.update(rp_id);
    m.final(&mac);

    // Calculated mac must match received mac
    return std.mem.eql(u8, cred_id[context_len..], &mac);
}

test "create ecdsa-p256 context" {
    const S = struct {
        pub fn rand(b: []u8) void {
            var r = std.rand.DefaultPrng.init(1);
            r.fill(b);
        }
    };

    const x = newContext(S.rand, cose.Algorithm.Es256);

    try std.testing.expectEqualSlices(u8, "\xF9\xFF\xFF\xFF", x[0..4]);
}
