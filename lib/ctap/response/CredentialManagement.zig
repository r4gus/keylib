const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

/// Number of existing discoverable credentials present on the authenticator
existingResidentCredentialsCount: ?u32 = null,
/// Number of maximum possible remaining discoverable credentials which can be created on the authenticator
maxPossibleRemainingResidentCredentialsCount: ?u32 = null,
/// RP Information
rp: ?fido.common.RelyingParty = null,
/// RP ID SHA-256 hash
rpIDHash: ?[32]u8 = null,
/// total number of RPs present on the authenticator
totalRPs: ?u32 = null,
/// User Information
user: ?fido.common.User = null,
/// PublicKeyCredentialDescriptor
credentialID: ?fido.common.PublicKeyCredentialDescriptor = null,
/// Public key of the credential
publicKey: ?[]const u8 = null,
/// Total number of credentials present on the authenticator for the RP in question
totalCredentials: ?u32 = null,
/// Credential protection policy
credProtect: ?fido.ctap.extensions.CredentialCreationPolicy = null,
/// Large blob encryption key
largeBlobKey: ?[]const u8 = null,

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .field_settings = &.{
            .{ .name = "existingResidentCredentialsCount", .alias = "1", .options = .{} },
            .{ .name = "maxPossibleRemainingResidentCredentialsCount", .alias = "2", .options = .{} },
            .{ .name = "rp", .alias = "3", .options = .{} },
            .{ .name = "rpIDHash", .alias = "4", .options = .{} },
            .{ .name = "totalRPs", .alias = "5", .options = .{} },
            .{ .name = "user", .alias = "6", .options = .{} },
            .{ .name = "credentialID", .alias = "7", .options = .{} },
            .{ .name = "publicKey", .alias = "8", .options = .{} },
            .{ .name = "totalCredentials", .alias = "9", .options = .{} },
            .{ .name = "credProtect", .alias = "10", .options = .{ .enum_as_text = false } },
            .{ .name = "largeBlobKey", .alias = "11", .options = .{} },
        },
        .from_cborStringify = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "existingResidentCredentialsCount", .alias = "1", .options = .{} },
            .{ .name = "maxPossibleRemainingResidentCredentialsCount", .alias = "2", .options = .{} },
            .{ .name = "rp", .alias = "3", .options = .{} },
            .{ .name = "rpIDHash", .alias = "4", .options = .{} },
            .{ .name = "totalRPs", .alias = "5", .options = .{} },
            .{ .name = "user", .alias = "6", .options = .{} },
            .{ .name = "credentialID", .alias = "7", .options = .{} },
            .{ .name = "publicKey", .alias = "8", .options = .{} },
            .{ .name = "totalCredentials", .alias = "9", .options = .{} },
            .{ .name = "credProtect", .alias = "10", .options = .{} },
            .{ .name = "largeBlobKey", .alias = "11", .options = .{} },
        },
    });
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.rp) |rp| {
        rp.deinit(allocator);
    }

    if (self.user) |user| {
        user.deinit(allocator);
    }

    if (self.credentialID) |credId| {
        credId.deinit(allocator);
    }

    if (self.publicKey) |pk| {
        allocator.free(pk);
    }

    if (self.largeBlobKey) |lbk| {
        allocator.free(lbk);
    }
}
