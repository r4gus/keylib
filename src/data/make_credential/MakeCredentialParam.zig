const std = @import("std");
const cbor = @import("zbor");

const RelyingParty = @import("../RelyingParty.zig");
const User = @import("../User.zig");
const CredParam = @import("../CredParam.zig");
const PublicKeyCredentialDescriptor = @import("../PublicKeyCredentialDescriptor.zig");
const AuthenticatorOptions = @import("../AuthenticatorOptions.zig");
const PinUvAuthParam = @import("../../crypto.zig").pin.PinUvAuthParam;

/// Hash of the ClientData contextual binding
clientDataHash: []const u8,
/// PublicKeyCredentialRpEntity
rp: RelyingParty,
/// PublicKeyCredentialUserEntity
user: User,
/// A sequence of CBOR maps
pubKeyCredParams: []const CredParam,
/// excludeList: A sequence of PublicKeyCredentialDescriptor structures.
/// The authenticator returns an error if the authenticator already contains
/// one of the credentials enumerated in this sequence.
excludeList: ?[]const PublicKeyCredentialDescriptor,
// TODO: add remaining fields (extensions 0x6)
/// authenticator options: Parameters to influence authenticator operation.
options: ?AuthenticatorOptions,
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?PinUvAuthParam,
/// PIN protocol version chosen by the client.
pinUvAuthProtocol: ?u8,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.clientDataHash);
    allocator.free(self.rp.id);
    if (self.rp.name) |name| {
        allocator.free(name);
    }
    allocator.free(self.user.id);
    if (self.user.name) |name| {
        allocator.free(name);
    }
    if (self.user.displayName) |name| {
        allocator.free(name);
    }

    for (self.pubKeyCredParams) |cp| {
        cp.deinit(allocator);
    }
    allocator.free(self.pubKeyCredParams);

    if (self.excludeList) |excludes| {
        for (excludes) |pkcd| {
            pkcd.deinit(allocator);
        }
        allocator.free(excludes);
    }
}

test "cred params" {
    const allocator = std.testing.allocator;

    const payload = "\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const cred_param = try cbor.parse(CredParam, try cbor.DataItem.new(payload), .{ .allocator = allocator });
    defer cred_param.deinit(allocator);

    try std.testing.expectEqual(cred_param.alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqualSlices(u8, "public-key", cred_param.type);
}

test "make credential" {
    const allocator = std.testing.allocator;

    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const di = try cbor.DataItem.new(payload);

    const mcp = try cbor.parse(@This(), di, .{
        .allocator = allocator,
        .field_settings = &.{
            .{ .name = "clientDataHash", .alias = "1", .options = .{} },
            .{ .name = "rp", .alias = "2", .options = .{} },
            .{ .name = "user", .alias = "3", .options = .{} },
            .{ .name = "pubKeyCredParams", .alias = "4", .options = .{} },
            .{ .name = "excludeList", .alias = "5", .options = .{} },
            .{ .name = "options", .alias = "7", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "8", .options = .{} },
            .{ .name = "pinUvAuthProtocol", .alias = "9", .options = .{} },
        },
    });
    defer mcp.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c", mcp.clientDataHash);
    try std.testing.expectEqualSlices(u8, "localhost", mcp.rp.id);
    try std.testing.expectEqualSlices(u8, "sweet home localhost", mcp.rp.name.?);
    try std.testing.expectEqualSlices(u8, "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49", mcp.user.id);
    try std.testing.expectEqualSlices(u8, "john smith", mcp.user.name.?);
    try std.testing.expectEqualSlices(u8, "jsmith", mcp.user.displayName.?);
    try std.testing.expectEqual(mcp.pubKeyCredParams[0].alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqualSlices(u8, "public-key", mcp.pubKeyCredParams[0].type);
}
