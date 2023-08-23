const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");

const Mac = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes256Ocb = std.crypto.aead.aes_ocb.Aes256Ocb;

/// Credential ID
_id: []const u8,

/// Revision (can be ignored for the most part)
_rev: ?[]const u8 = null,

user_id: []const u8,

user_name: ?[]const u8 = null,

user_display_name: ?[]const u8 = null,

/// The ID of the Relying Party (usually a base URL)
rp_id: []const u8,

/// Number of signatures issued using the given credential
sign_count: u64,

/// Signature algorithm to use for the credential
alg: cbor.cose.Algorithm,

/// The AES-OCB encrypted private key
private_key: []const u8 = undefined,

policy: fido.ctap.extensions.CredentialCreationPolicy = .userVerificationOptional,

/// Belongs to hmac secret
cred_random_with_uv: [32]u8 = undefined,

/// Belongs to hmac secret
cred_random_without_uv: [32]u8 = undefined,

/// Message Authentication Code over the remaining data
mac: [Mac.mac_length]u8 = undefined,

pub fn allocInit(
    raw_id: []const u8,
    user: *const fido.common.User,
    rp_id: []const u8,
    alg: cbor.cose.Algorithm,
    policy: fido.ctap.extensions.CredentialCreationPolicy,
    allocator: std.mem.Allocator,
    rand: std.rand.Random,
) !@This() {
    var self = @This(){
        ._id = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexUpper(raw_id)}),
        .user_id = try allocator.dupe(u8, user.id),
        .rp_id = try allocator.dupe(u8, rp_id),
        .sign_count = 0,
        .alg = alg,
        .policy = policy,
    };

    if (user.name) |name| {
        self.user_name = try allocator.dupe(u8, name);
    }
    if (user.displayName) |name| {
        self.user_display_name = try allocator.dupe(u8, name);
    }

    rand.bytes(self.cred_random_with_uv[0..]);
    rand.bytes(self.cred_random_without_uv[0..]);

    self.sign_count = 0;

    return self;
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self._id);
    if (self._rev) |rev| {
        allocator.free(rev);
    }
    allocator.free(self.user_id);
    if (self.user_name) |name| {
        allocator.free(name);
    }
    if (self.user_display_name) |name| {
        allocator.free(name);
    }
    allocator.free(self.rp_id);
    allocator.free(self.private_key);
}

pub fn setPrivateKey(
    self: *@This(),
    private_key: []const u8,
    key: [Aes256Ocb.key_length]u8,
    rand: std.rand.Random,
    allocator: std.mem.Allocator,
) !void {
    var m = try allocator.alloc(u8, Aes256Ocb.nonce_length + Aes256Ocb.tag_length + private_key.len);
    rand.bytes(m[0..Aes256Ocb.nonce_length]);
    Aes256Ocb.encrypt(
        m[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        m[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length],
        private_key[0..],
        "",
        m[0..Aes256Ocb.nonce_length].*,
        key,
    );
    self.private_key = m;
}

pub fn getPrivateKey(
    self: *const @This(),
    key: [Aes256Ocb.key_length]u8,
    allocator: std.mem.Allocator,
) ![]const u8 {
    var m = try allocator.alloc(u8, self.private_key.len - Aes256Ocb.nonce_length - Aes256Ocb.tag_length);
    try Aes256Ocb.decrypt(
        m,
        self.private_key[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        self.private_key[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length].*,
        "",
        self.private_key[0..Aes256Ocb.nonce_length].*,
        key,
    );

    return m;
}

pub fn updateMac(self: *@This(), key: []const u8) void {
    var m = Mac.init(key);
    m.update(self._id);
    m.update(self.user_id);
    m.update(self.rp_id);
    m.update(std.mem.asBytes(&self.sign_count));
    m.update(std.mem.asBytes(&self.alg));
    m.update(self.private_key);
    m.update(std.mem.asBytes(&self.policy));
    m.update(&self.cred_random_with_uv);
    m.update(&self.cred_random_without_uv);
    m.final(&self.mac);
}

pub fn verifyMac(self: *@This(), key: []const u8) bool {
    var x: [Mac.mac_length]u8 = undefined;
    var m = Mac.init(key);
    m.update(self._id);
    m.update(self.user_id);
    m.update(self.rp_id);
    m.update(std.mem.asBytes(&self.sign_count));
    m.update(std.mem.asBytes(&self.alg));
    m.update(self.private_key);
    m.update(std.mem.asBytes(&self.policy));
    m.update(&self.cred_random_with_uv);
    m.update(&self.cred_random_without_uv);
    m.final(&x);

    return std.mem.eql(u8, x[0..], self.mac[0..]);
}

test "Credential mac #1" {
    const k = "\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

    var x = @This(){
        ._id = "credential1",
        .user_id = "12345",
        .rp_id = "github.com",
        .sign_count = 89,
        .alg = .Es256,
        .private_key = "privatekey",
    };
    x.updateMac(k);
    try std.testing.expectEqual(true, x.verifyMac(k));

    x.sign_count += 1;
    try std.testing.expectEqual(false, x.verifyMac(k));
}

test "Credential encrypt/decrypt #1" {
    const allocator = std.testing.allocator;
    const k = "\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

    var x = @This(){
        ._id = "credential1",
        .user_id = "12345",
        .rp_id = "github.com",
        .sign_count = 89,
        .alg = .Es256,
    };
    try x.setPrivateKey("privatekey", k.*, std.crypto.random, allocator);
    defer allocator.free(x.private_key);
    const m = try x.getPrivateKey(k.*, allocator);
    defer allocator.free(m);

    try std.testing.expectEqualSlices(u8, "privatekey", m);
}
