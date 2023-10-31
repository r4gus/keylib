const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

/// The sub command currently being requested
subCommand: SubCommand,
/// Map of sub command parameters
subCommandParams: ?SubCommandParams = null,
/// PIN/UV protocol version chosen by the platform
pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,
/// First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken
pinUvAuthParam: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.subCommandParams) |subCommandParams| {
        subCommandParams.deinit(allocator);
    }

    if (self.pinUvAuthParam) |puap| {
        allocator.free(puap);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .field_settings = &.{
            .{ .name = "subCommand", .alias = "1", .options = .{ .enum_as_text = false } },
            .{ .name = "subCommandParams", .alias = "2", .options = .{} },
            .{ .name = "pinUvAuthProtocol", .alias = "3", .options = .{ .enum_as_text = false } },
            .{ .name = "pinUvAuthParam", .alias = "4", .options = .{} },
        },
        .from_cborStringify = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "subCommand", .alias = "1", .options = .{} },
            .{ .name = "subCommandParams", .alias = "2", .options = .{} },
            .{ .name = "pinUvAuthProtocol", .alias = "3", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "4", .options = .{} },
        },
    });
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/// List of sub commands for credential management
pub const SubCommand = enum(u8) {
    /// get credentials metadata information
    getCredsMetadata = 0x01,
    enumerateRPsBegin = 0x02,
    enumerateRPsGetNextRP = 0x03,
    enumerateCredentialsBegin = 0x04,
    enumerateCredentialsGetNextCredential = 0x05,
    deleteCredential = 0x06,
    updateUserInformation = 0x07,
};

pub const SubCommandParams = struct {
    /// RP ID SHA-256 hash
    rpIDHash: ?[32]u8 = null,
    /// Credential identifier
    credentialID: ?fido.common.PublicKeyCredentialDescriptor = null,
    /// User Entity
    user: ?fido.common.User = null,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        if (self.credentialID) |credId| {
            credId.deinit(allocator);
        }

        if (self.user) |user| {
            user.deinit(allocator);
        }
    }

    pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
        _ = options;

        try cbor.stringify(self, .{
            .field_settings = &.{
                .{ .name = "rpIDHash", .alias = "1", .options = .{ .slice_as_text = false } },
                .{ .name = "credentialID", .alias = "2", .options = .{} },
                .{ .name = "user", .alias = "3", .options = .{} },
            },
            .from_cborStringify = true,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
        return try cbor.parse(@This(), item, .{
            .allocator = options.allocator,
            .from_cborParse = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "rpIDHash", .alias = "1", .options = .{ .slice_as_text = false } },
                .{ .name = "credentialID", .alias = "2", .options = .{} },
                .{ .name = "user", .alias = "3", .options = .{} },
            },
        });
    }
};
