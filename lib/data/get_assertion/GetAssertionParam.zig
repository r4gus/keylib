const std = @import("std");

const PublicKeyCredentialDescriptor = @import("../PublicKeyCredentialDescriptor.zig");
const AuthenticatorOptions = @import("../AuthenticatorOptions.zig");
const PinProtocol = @import("../client_pin/pin_protocol.zig").PinProtocol;

/// Relying party identifier.
rpId: [:0]const u8, // 1
/// Hash of the serialized client data collected by the host.
clientDataHash: []const u8, // 2
/// A sequence of PublicKeyCredentialDescriptor structures, each
/// denoting a credential, as specified in [WebAuthN]. If this parameter is
/// present and has 1 or more entries, the authenticator MUST only generate
/// an assertion using one of the denoted credentials.
allowList: ?[]const PublicKeyCredentialDescriptor = null, // 3
// TODO: add remaining fields (extensions 0x4)
/// Parameters to influence authenticator operation.
options: ?AuthenticatorOptions = null, // 5
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?[32]u8 = null, // 6
/// PIN protocol version selected by client.
pinUvAuthProtocol: ?PinProtocol = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.rpId);
    allocator.free(self.clientDataHash);
    if (self.allowList) |pkcds| {
        for (pkcds) |pkcd| {
            pkcd.deinit(allocator);
        }
        allocator.free(pkcds);
    }
}

const cbor = @import("zbor");

test "get assertion 1" {
    const allocator = std.testing.allocator;

    const payload = "\xa6\x01\x6b\x77\x65\x62\x61\x75\x74\x68\x6e\x2e\x69\x6f\x02\x58\x20\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b\x03\x81\xa2\x62\x69\x64\x58\x40\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x05\xa1\x62\x75\x70\xf4\x06\x58\x20\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10\x07\x02";

    const di = try cbor.DataItem.new(payload);

    const get_assertion_param = try cbor.parse(
        @This(),
        di,
        .{
            .allocator = allocator,
            .field_settings = &.{
                .{ .name = "rpId", .alias = "1", .options = .{} },
                .{ .name = "clientDataHash", .alias = "2", .options = .{} },
                .{ .name = "allowList", .alias = "3", .options = .{} },
                .{ .name = "options", .alias = "5", .options = .{} },
                .{ .name = "pinUvAuthParam", .alias = "6", .options = .{} },
                .{ .name = "pinUvAuthProtocol", .alias = "7", .options = .{} },
            },
        },
    );
    defer get_assertion_param.deinit(allocator);

    try std.testing.expectEqual(false, get_assertion_param.options.?.up.?);
}
