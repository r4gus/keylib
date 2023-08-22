const std = @import("std");
const fido = @import("../../main.zig");

const Mac = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes256Ocb = std.crypto.aead.aes_ocb.Aes256Ocb;
const argon2 = std.crypto.pwhash.argon2;
const master_secret = fido.ctap.crypto.master_secret;

pub const KEY_LEN = Aes256Ocb.key_length;

pub const Keys = struct {
    mac: [KEY_LEN]u8,
    enc: [KEY_LEN]u8,
};

_id: [8]u8 = "Settings".*,
_rev: ?[]const u8 = null,
/// Number of retries left
retries: u8 = 8,
/// Pin has to be changed
force_pin_change: bool = false,
/// The minimum pin length
min_pin_length: u8 = 4,
/// Enforce user verification
always_uv: bool = true,
/// Master secret encrypted using AES-OCB
secret: [Aes256Ocb.nonce_length + Aes256Ocb.tag_length + master_secret.MS_LEN]u8 = undefined,
/// Pin with a max length of 63 bytes
pin: ?[Aes256Ocb.nonce_length + Aes256Ocb.tag_length + 33]u8 = null,
/// Message Authentication Code over the remaining data
mac: [Mac.mac_length]u8 = undefined,
kdf: struct {
    salt: [8]u8 = undefined,
    // recommendation by OWASP
    P: u24 = 1,
    M: u32 = 7168,
    I: u32 = 5,
} = .{},

pub fn newKey(
    self: *@This(),
    password: []const u8,
    random: std.rand.Random,
    a: std.mem.Allocator,
) !Keys {
    random.bytes(self.kdf.salt[0..]);
    return try self.deriveKey(password, a);
}

pub fn deriveKey(
    self: *@This(),
    password: []const u8,
    a: std.mem.Allocator,
) !Keys {
    var k: [KEY_LEN + KEY_LEN]u8 = undefined;
    try argon2.kdf(
        a,
        k[0..],
        password,
        self.kdf.salt[0..],
        .{ .t = self.kdf.I, .m = self.kdf.M, .p = self.kdf.P },
        .argon2id,
    );
    return Keys{
        .max = k[0..KEY_LEN].*,
        .enc = k[KEY_LEN..].*,
    };
}

pub fn updateMac(self: *@This(), key: []const u8) void {
    var m = Mac.init(key);
    m.update(&self._id);
    m.update(std.mem.asBytes(&self.retries));
    m.update(std.mem.asBytes(&self.force_pin_change));
    m.update(std.mem.asBytes(&self.min_pin_length));
    m.update(std.mem.asBytes(&self.always_uv));
    m.update(&self.secret);
    if (self.pin) |pin| {
        m.update(&pin);
    }
    m.final(&self.mac);
}

pub fn verifyMac(self: *@This(), key: []const u8) bool {
    var x: [Mac.mac_length]u8 = undefined;
    var m = Mac.init(key);
    m.update(&self._id);
    m.update(std.mem.asBytes(&self.retries));
    m.update(std.mem.asBytes(&self.force_pin_change));
    m.update(std.mem.asBytes(&self.min_pin_length));
    m.update(std.mem.asBytes(&self.always_uv));
    m.update(&self.secret);
    if (self.pin) |pin| {
        m.update(&pin);
    }
    m.final(&x);

    return std.mem.eql(u8, x[0..], self.mac[0..]);
}

pub fn setSecret(
    self: *@This(),
    secret: master_secret.MasterSecret,
    key: [Aes256Ocb.key_length]u8,
    rand: std.rand.Random,
) void {
    rand.bytes(self.secret[0..Aes256Ocb.nonce_length]);
    Aes256Ocb.encrypt(
        self.secret[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        self.secret[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length],
        secret[0..],
        "",
        self.secret[0..Aes256Ocb.nonce_length].*,
        key,
    );
}

pub fn getSecret(
    self: *const @This(),
    key: [Aes256Ocb.key_length]u8,
) !master_secret.MasterSecret {
    var m: master_secret.MasterSecret = undefined;

    try Aes256Ocb.decrypt(
        &m,
        self.secret[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        self.secret[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length].*,
        "",
        self.secret[0..Aes256Ocb.nonce_length].*,
        key,
    );

    return m;
}

pub fn setPin(
    self: *@This(),
    pin: [32]u8,
    code_points: u8,
    key: [Aes256Ocb.key_length]u8,
    rand: std.rand.Random,
) !void {
    var p: [33]u8 = .{0} ** 33;
    @memcpy(p[0..32], pin[0..32]);
    p[32] = code_points;

    self.pin = .{0} ** (Aes256Ocb.nonce_length + Aes256Ocb.tag_length + 33);
    rand.bytes(self.pin.?[0..Aes256Ocb.nonce_length]);
    Aes256Ocb.encrypt(
        self.pin.?[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        self.pin.?[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length],
        p[0..],
        "",
        self.pin.?[0..Aes256Ocb.nonce_length].*,
        key,
    );
}

pub fn getPin(
    self: *const @This(),
    key: [Aes256Ocb.key_length]u8,
    code_points: *u8,
) ![32]u8 {
    if (self.pin == null) return error.NoPinSet;

    var m: [33]u8 = undefined;

    try Aes256Ocb.decrypt(
        &m,
        self.pin.?[Aes256Ocb.nonce_length + Aes256Ocb.tag_length ..],
        self.pin.?[Aes256Ocb.nonce_length .. Aes256Ocb.nonce_length + Aes256Ocb.tag_length].*,
        "",
        self.pin.?[0..Aes256Ocb.nonce_length].*,
        key,
    );

    code_points.* = m[32];
    return m[0..32].*;
}

test "Meta mac #1" {
    const k = "\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    const secret: [32]u8 = "012345679abcdefg012345679abcdefg".*;

    var x = @This(){};
    x.setSecret(secret, k.*, std.crypto.random);
    x.updateMac(k);

    try std.testing.expectEqual(true, x.verifyMac(k));

    x.retries -= 1;
    try std.testing.expectEqual(false, x.verifyMac(k));

    x.retries += 1;
    x.force_pin_change = true;
    try std.testing.expectEqual(false, x.verifyMac(k));

    x.force_pin_change = false;
    try std.testing.expectEqual(true, x.verifyMac(k));
}

test "Meta encrypt/decrypt #1" {
    const k = "\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    const secret: [32]u8 = "012345679abcdefg012345679abcdefg".*;

    var x = @This(){};
    x.setSecret(secret, k.*, std.crypto.random);
    const m = try x.getSecret(k.*);

    try std.testing.expectEqualSlices(u8, "012345679abcdefg012345679abcdefg", &m);
}
