const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const RelyingParty = fido.common.RelyingParty;
const User = fido.common.User;
const PublicKeyCredentialParameters = fido.common.PublicKeyCredentialParameters;
const PublicKeyCredentialDescriptor = fido.common.PublicKeyCredentialDescriptor;
const AuthenticatorOptions = fido.common.AuthenticatorOptions;

const PinUvAuthParam = fido.pinuv.common.PinUvAuthParam;
const PinProtocol = fido.pinuv.common.PinProtocol;

/// Hash of the ClientData contextual binding
clientDataHash: []const u8,
/// PublicKeyCredentialRpEntity
rp: RelyingParty,
/// PublicKeyCredentialUserEntity
user: User,
/// A sequence of CBOR maps
pubKeyCredParams: []const PublicKeyCredentialParameters,
/// excludeList: A sequence of PublicKeyCredentialDescriptor structures.
/// The authenticator returns an error if the authenticator already contains
/// one of the credentials enumerated in this sequence.
excludeList: ?[]const PublicKeyCredentialDescriptor = null,
/// authenticator options: Parameters to influence authenticator operation.
options: ?AuthenticatorOptions = null,
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?PinUvAuthParam = null,
/// PIN protocol version chosen by the client.
pinUvAuthProtocol: ?PinProtocol = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.clientDataHash);
    self.rp.deinit(allocator);
    self.user.deinit(allocator);
    allocator.free(self.pubKeyCredParams);
    if (self.excludeList) |excludes| {
        for (excludes) |pkcd| {
            pkcd.deinit(allocator);
        }
        allocator.free(excludes);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    return cbor.stringify(self, .{
        .allocator = options.allocator,
        .from_cborStringify = true,
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
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
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
}

test "make credential parse 1" {
    const allocator = std.testing.allocator;

    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const di = try cbor.DataItem.new(payload);

    const mcp = try cbor.parse(@This(), di, .{
        .allocator = allocator,
    });
    defer mcp.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c", mcp.clientDataHash);
    try std.testing.expectEqualSlices(u8, "localhost", mcp.rp.id);
    try std.testing.expectEqualSlices(u8, "sweet home localhost", mcp.rp.name.?);
    try std.testing.expectEqualSlices(u8, "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49", mcp.user.id);
    try std.testing.expectEqualSlices(u8, "john smith", mcp.user.name.?);
    try std.testing.expectEqualSlices(u8, "jsmith", mcp.user.displayName.?);
    try std.testing.expectEqual(mcp.pubKeyCredParams[0].alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqual(mcp.pubKeyCredParams[0].type, .@"public-key");
}

test "make credential stringify 1" {
    const allocator = std.testing.allocator;
    var x = std.ArrayList(u8).init(allocator);
    defer x.deinit();

    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const mcp = @This(){
        .clientDataHash = "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c",
        .rp = .{
            .id = "localhost",
            .name = "sweet home localhost",
        },
        .user = .{
            .id = "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49",
            .name = "john smith",
            .displayName = "jsmith",
        },
        .pubKeyCredParams = &.{
            .{ .alg = .Es256, .type = .@"public-key" },
        },
    };

    try cbor.stringify(mcp, .{}, x.writer());

    try std.testing.expectEqualSlices(u8, payload, x.items);
}