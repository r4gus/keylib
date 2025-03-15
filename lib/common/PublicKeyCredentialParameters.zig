const std = @import("std");
const cbor = @import("zbor");
const PublicKeyCredentialType = @import("PublicKeyCredentialType.zig").PublicKeyCredentialType;

/// This member specifies the cryptographic signature algorithm with which
/// the newly generated credential will be used, and thus also the type of
/// asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
alg: cbor.cose.Algorithm,
/// The type of credential to be created. The value SHOULD be a member of
/// PublicKeyCredentialType but client platforms MUST ignore unknown values,
/// ignoring any PublicKeyCredentialParameters with an unknown type.
type: PublicKeyCredentialType = .@"public-key",

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;
    return cbor.stringify(self, .{
        .ignore_override = true,
        .field_settings = &.{
            .{ .name = "alg", .value_options = .{ .enum_serialization_type = .Integer } },
        },
    }, out);
}

test "PublicKeyCredentialDescriptor test 1" {
    const di = try cbor.DataItem.new("\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79");

    const c = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqual(cbor.cose.Algorithm.Es256, c.alg);
    try std.testing.expectEqual(PublicKeyCredentialType.@"public-key", c.type);
}

test "PublicKeyCredentialDescriptor test 2" {
    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    const desc = @This(){
        .alg = .Es256,
    };

    try cbor.stringify(desc, .{}, str.writer());

    try std.testing.expectEqualSlices(u8, "\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79", str.items);
}
