const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const PinUvAuthParam = fido.ctap.pinuv.common.PinUvAuthParam;
const PinProtocol = fido.ctap.pinuv.common.PinProtocol;

const ClientDataHash = fido.ctap.crypto.ClientDataHash;

/// Relying party identifier.
rpId: [:0]const u8, // 1
/// Hash of the serialized client data collected by the host.
clientDataHash: ClientDataHash, // 2
/// A sequence of PublicKeyCredentialDescriptor structures, each
/// denoting a credential, as specified in [WebAuthN]. If this parameter is
/// present and has 1 or more entries, the authenticator MUST only generate
/// an assertion using one of the denoted credentials.
allowList: ?[]const fido.common.PublicKeyCredentialDescriptor = null, // 3
extensions: ?fido.ctap.extensions.Extensions = null,
/// Parameters to influence authenticator operation.
options: ?fido.common.AuthenticatorOptions = null, // 5
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?PinUvAuthParam = null, // 6
/// PIN protocol version selected by client.
pinUvAuthProtocol: ?PinProtocol = null,
enterpriseAttestation: ?u64 = null,
attestationFormatsPreference: ?[]const fido.common.AttestationStatementFormatIdentifiers = null,

pub fn requestsUv(self: *const @This()) bool {
    return self.options != null and self.options.?.uv != null and self.options.?.uv.?;
}

pub fn requestsRk(self: *const @This()) bool {
    return self.options != null and self.options.?.rk != null and self.options.?.rk.?;
}

pub fn requestsUp(self: *const @This()) bool {
    // if up missing treat it as being present with the value true
    return if (self.options != null and self.options.?.up != null) self.options.?.up.? else true;
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.rpId);
    if (self.allowList) |pkcds| {
        for (pkcds) |pkcd| {
            pkcd.deinit(allocator);
        }
        allocator.free(pkcds);
    }
    if (self.attestationFormatsPreference) |pref| {
        allocator.free(pref);
    }
    if (self.pinUvAuthParam) |param| {
        allocator.free(param);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    return cbor.stringify(self, .{
        .allocator = options.allocator,
        .from_cborStringify = true,
        .field_settings = &.{
            .{ .name = "rpId", .alias = "1", .options = .{} },
            .{ .name = "clientDataHash", .alias = "2", .options = .{} },
            .{ .name = "allowList", .alias = "3", .options = .{} },
            .{ .name = "options", .alias = "5", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "6", .options = .{} },
            .{ .name = "pinUvAuthProtocol", .alias = "7", .options = .{ .enum_as_text = false } },
            .{ .name = "enterpriseAttestation", .alias = "8", .options = .{} },
            .{ .name = "attestationFormatsPreference", .alias = "9", .options = .{ .enum_as_text = false } },
        },
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "rpId", .alias = "1", .options = .{} },
            .{ .name = "clientDataHash", .alias = "2", .options = .{} },
            .{ .name = "allowList", .alias = "3", .options = .{} },
            .{ .name = "options", .alias = "5", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "6", .options = .{} },
            .{ .name = "pinUvAuthProtocol", .alias = "7", .options = .{} },
            .{ .name = "enterpriseAttestation", .alias = "8", .options = .{} },
            .{ .name = "attestationFormatsPreference", .alias = "9", .options = .{ .enum_as_text = false } },
        },
    });
}

test "get assertion parse 1" {
    const allocator = std.testing.allocator;

    const payload = "\xa6\x01\x6b\x77\x65\x62\x61\x75\x74\x68\x6e\x2e\x69\x6f\x02\x58\x20\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b\x03\x81\xa2\x62\x69\x64\x58\x40\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x05\xa1\x62\x75\x70\xf4\x06\x58\x20\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10\x07\x02";

    const di = try cbor.DataItem.new(payload);

    const get_assertion_param = try cbor.parse(@This(), di, .{ .allocator = allocator });
    defer get_assertion_param.deinit(allocator);

    try std.testing.expectEqualStrings("webauthn.io", get_assertion_param.rpId);
    try std.testing.expectEqualSlices(u8, "\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b", &get_assertion_param.clientDataHash);
    try std.testing.expectEqual(@as(usize, @intCast(1)), get_assertion_param.allowList.?.len);
    try std.testing.expectEqualSlices(u8, "\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0", get_assertion_param.allowList.?[0].id);
    try std.testing.expectEqual(fido.common.PublicKeyCredentialType.@"public-key", get_assertion_param.allowList.?[0].type);
    try std.testing.expectEqual(false, get_assertion_param.options.?.up.?);
    try std.testing.expectEqualSlices(u8, "\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10", get_assertion_param.pinUvAuthParam.?);
    try std.testing.expectEqual(PinProtocol.V2, get_assertion_param.pinUvAuthProtocol.?);
}

test "get assertion stringify 1" {
    const allocator = std.testing.allocator;
    var x = std.ArrayList(u8).init(allocator);
    defer x.deinit();

    const payload = "\xa6\x01\x6b\x77\x65\x62\x61\x75\x74\x68\x6e\x2e\x69\x6f\x02\x58\x20\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b\x03\x81\xa2\x62\x69\x64\x58\x40\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x05\xa1\x62\x75\x70\xf4\x06\x58\x20\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10\x07\x02";

    const gap = @This(){
        .rpId = "webauthn.io",
        .clientDataHash = "\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b".*,
        .allowList = &.{fido.common.PublicKeyCredentialDescriptor{
            .id = "\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0",
            .type = .@"public-key",
        }},
        .options = .{
            .up = false,
            .rk = null,
            .uv = null,
        },
        .pinUvAuthParam = "\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10",
        .pinUvAuthProtocol = .V2,
    };

    try cbor.stringify(gap, .{}, x.writer());

    try std.testing.expectEqualSlices(u8, payload, x.items);
}
