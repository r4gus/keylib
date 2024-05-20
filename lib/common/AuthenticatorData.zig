//! The authenticator data structure encodes contextual bindings made by the
//! authenticator. These bindings are controlled by the authenticator itself,
//! and derive their trust from the WebAuthn Relying Party's assessment of
//! the security properties of the authenticator.
//!
//! The authenticator data structure is a byte array of 37 bytes or more

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../main.zig");

/// SHA-256 hash of the RP ID the credential is scoped to
rpIdHash: [32]u8,
/// Flags providing additional context to the given data
flags: packed struct(u8) {
    /// User Present (UP) result.
    /// - 1 means the user is present.
    /// - 0 means the user is not present.
    up: u1,
    /// Reserved for future use.
    rfu1: u1,
    /// User Verified (UV) result.
    /// - 1 means the user is verified.
    /// - 0 means the user is not verified.
    uv: u1,
    /// Reserved for future use.
    rfu2: u3,
    /// Attested credential data includet (AT).
    /// Indicates whether the authenticator added attested
    /// credential data.
    at: u1,
    /// Extension data included (ED).
    /// Indicates if the authenticator data has extensions.
    ed: u1,
},
/// Signature counter, 32-bit unsigned big-endian integer
signCount: u32,
/// Attested credential data
///
/// One could say this is the most important chunk of data because it contains
/// the credential (public key + cred_id) to be stored by the RP
attestedCredentialData: ?fido.common.AttestedCredentialData = null,
extensions: ?fido.ctap.extensions.Extensions = null,

/// Encode the given AuthenticatorData as byte array
pub fn encode(self: *const @This(), out: anytype) !void {
    try out.writeAll(self.rpIdHash[0..]);
    try out.writeByte(@as(u8, @bitCast(self.flags)));

    // counter is encoded in big-endian format
    try out.writeByte(@as(u8, @intCast((self.signCount >> 24) & 0xff)));
    try out.writeByte(@as(u8, @intCast((self.signCount >> 16) & 0xff)));
    try out.writeByte(@as(u8, @intCast((self.signCount >> 8) & 0xff)));
    try out.writeByte(@as(u8, @intCast(self.signCount & 0xff)));

    if (self.attestedCredentialData) |acd| {
        try acd.encode(out);
    }
}

test "authData encoding" {
    const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    const allocator = std.testing.allocator;
    var a = std.ArrayList(u8).init(allocator);
    defer a.deinit();

    const k = cbor.cose.Key.fromP256Pub(.Es256, try EcdsaP256Sha256.PublicKey.fromSec1("\x04\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52"));
    var serialized_cred = std.ArrayList(u8).init(allocator);
    defer serialized_cred.deinit();
    try cbor.stringify(&k, .{ .enum_serialization_type = .Integer }, serialized_cred.writer());

    const acd = try fido.common.AttestedCredentialData.new(
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        &.{ 0xb3, 0xf8, 0xcd, 0xb1, 0x80, 0x20, 0x91, 0x76, 0xfa, 0x20, 0x1a, 0x51, 0x6d, 0x1b, 0x42, 0xf8, 0x02, 0xa8, 0x0d, 0xaf, 0x48, 0xd0, 0x37, 0x88, 0x21, 0xa6, 0xfb, 0xdd, 0x52, 0xde, 0x16, 0xb7, 0xef, 0xf6, 0x22, 0x25, 0x72, 0x43, 0x8d, 0xe5, 0x85, 0x7e, 0x70, 0xf9, 0xef, 0x05, 0x80, 0xe9, 0x37, 0xe3, 0x00, 0xae, 0xd0, 0xdf, 0xf1, 0x3f, 0xb6, 0xa3, 0x3e, 0xc3, 0x8b, 0x81, 0xca, 0xd0 },
        serialized_cred.items,
    );

    const ad = @This(){
        .rpIdHash = .{ 0x21, 0x09, 0x18, 0x5f, 0x69, 0x3a, 0x01, 0xea, 0x1a, 0x26, 0x41, 0xf8, 0x2d, 0x52, 0xfb, 0xae, 0xee, 0x0a, 0x4f, 0x47, 0xe3, 0x37, 0x4d, 0xfe, 0xf8, 0x70, 0x83, 0x8d, 0xe4, 0x9b, 0x0e, 0x97 },
        .flags = .{
            .up = 1,
            .rfu1 = 0,
            .uv = 0,
            .rfu2 = 0,
            .at = 1,
            .ed = 0,
        },
        .signCount = 0,
        .attestedCredentialData = acd,
    };

    const w = a.writer();
    try ad.encode(w);

    try std.testing.expectEqualSlices(u8, a.items, "\x21\x09\x18\x5f\x69\x3a\x01\xea\x1a\x26\x41\xf8\x2d\x52\xfb\xae\xee\x0a\x4f\x47\xe3\x37\x4d\xfe\xf8\x70\x83\x8d\xe4\x9b\x0e\x97\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\xb3\xf8\xcd\xb1\x80\x20\x91\x76\xfa\x20\x1a\x51\x6d\x1b\x42\xf8\x02\xa8\x0d\xaf\x48\xd0\x37\x88\x21\xa6\xfb\xdd\x52\xde\x16\xb7\xef\xf6\x22\x25\x72\x43\x8d\xe5\x85\x7e\x70\xf9\xef\x05\x80\xe9\x37\xe3\x00\xae\xd0\xdf\xf1\x3f\xb6\xa3\x3e\xc3\x8b\x81\xca\xd0\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\x22\x58\x20\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52");
}
