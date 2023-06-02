//! Response of a client pin command

const std = @import("std");

const cbor = @import("zbor");

/// Authenticator key agreement public key in COSE_Key format. This will
/// be used to establish a sharedSecret between platform and the authenticator.
keyAgreement: ?cbor.cose.Key = null,
/// Encrypted pinToken using sharedSecret to be used in
/// subsequent authenticatorMakeCredential and
/// authenticatorGetAssertion operations.
pinUvAuthToken: ?[]const u8 = null,
/// Number of PIN attempts remaining before lockout. This
/// is optionally used to show in UI when collecting the PIN in
/// Setting a new PIN, Changing existing PIN and Getting pinToken
/// from the authenticator flows.
pinRetries: ?u8 = null,
/// Present and true if the authenticator requires a power
/// cycle before any future PIN operation, false if no power cycle needed.
powerCycleState: ?bool = null,
/// Number of uv attempts remaining before lockout.
uvRetries: ?u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.pinUvAuthToken) |pinUvAuthToken| {
        allocator.free(pinUvAuthToken);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "keyAgreement", .alias = "1", .options = .{ .enum_as_text = false } },
            .{ .name = "pinUvAuthToken", .alias = "2", .options = .{} },
            .{ .name = "pinRetries", .alias = "3", .options = .{} },
            .{ .name = "powerCycleState", .alias = "4", .options = .{} },
            .{ .name = "uvRetries", .alias = "5", .options = .{} },
        },
        .from_cborStringify = true,
    }, out);
}
