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

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthToken", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "pinRetries", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "powerCycleState", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "uvRetries", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
        },
        .from_callback = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_callback = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthToken", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "pinRetries", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "powerCycleState", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "uvRetries", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
        },
    });
}
