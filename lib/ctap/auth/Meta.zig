const std = @import("std");
const fido = @import("../../main.zig");

const Mac = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes256Ocb = std.crypto.aead.aes_ocb.Aes256Ocb;
const master_secret = fido.ctap.crypto.master_secret;

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
/// Message Authentication Code over the remaining data
mac: [Mac.mac_length]u8 = undefined,

pub fn updateMac(self: *@This(), key: []const u8) void {
    var m = Mac.init(key);
    m.update(std.mem.asBytes(&self.retries));
    m.update(std.mem.asBytes(&self.force_pin_change));
    m.update(std.mem.asBytes(&self.min_pin_length));
    m.update(std.mem.asBytes(&self.always_uv));
    m.update(&self.secret);
    m.final(&self.mac);
}

pub fn verifyMac(self: *@This(), key: []const u8) bool {
    var x: [Mac.mac_length]u8 = undefined;
    var m = Mac.init(key);
    m.update(std.mem.asBytes(&self.retries));
    m.update(std.mem.asBytes(&self.force_pin_change));
    m.update(std.mem.asBytes(&self.min_pin_length));
    m.update(std.mem.asBytes(&self.always_uv));
    m.update(&self.secret);
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
