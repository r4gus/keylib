//! Authenticator settings that influence its behaviour
//!
//! The settings also represent the data returned by a call to
//! the getInfo command.

/// List of supported versions.
versions: []const @import("versions.zig").Versions,
//TODO: extensions: List of supported extensions.
// @"2": ?[]const extension.Extensions,
/// The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
/// indicating the type of the authenticator. Authenticators with the
/// same capabilities and firmware, can share the same AAGUID.
aaguid: [16]u8,

/// Supported options.
options: ?@import("Options.zig") = null,

/// Maximum message size supported by the authenticator.
/// null = unlimited.
max_msg_size: ?u64 = null,

/// List of supported PIN Protocol versions.
pin_uv_auth_protocols: []const @import("client_pin.zig").PinProtocol,

/// Maximum number of credentials supported in credentialID list at a time
/// by the authenticator. MUST be greater than zero if present.
max_credential_count_id_list: ?u64 = null,

/// Maximum Credential ID Length supported by the authenticator. MUST
/// be greater than zero if present.
max_credential_id_length: ?u64 = null,

/// List of supported transports.
transports: ?[]const @import("transports.zig").Transports = null,

/// List of supported algorithms
algorithms: ?[]const @import("Algorithm.zig") = null,

/// A pin change is required Y/n
force_pin_change: ?bool = null,

/// Minimum pin length required
min_pin_length: ?u64 = null,

/// Indicates the firmware version of the authenticator model identified by AAGUID.
/// Whenever releasing any code change to the authenticator firmware, authenticator
/// MUST increase the version.
firmware_version: ?u64 = null,

const cbor = @import("zbor");
pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "versions", .alias = "1", .options = .{} },
            .{ .name = "aaguid", .alias = "3", .options = .{} },
            .{ .name = "options", .alias = "4", .options = .{} },
            .{ .name = "max_msg_size", .alias = "5", .options = .{} },
            .{ .name = "pin_uv_auth_protocols", .alias = "6", .options = .{ .enum_as_text = false } },
            .{ .name = "max_credential_count_id_list", .alias = "7", .options = .{} },
            .{ .name = "max_credential_id_length", .alias = "8", .options = .{} },
            .{ .name = "transports", .alias = "9", .options = .{} },
            .{ .name = "algorithms", .alias = "10", .options = .{ .enum_as_text = false } },
            .{ .name = "force_pin_change", .alias = "12", .options = .{} },
            .{ .name = "min_pin_length", .alias = "13", .options = .{} },
            .{ .name = "firmware_version", .alias = "14", .options = .{} },
        },
        .from_cborStringify = true,
    }, out);
}

test "Serialize authenticator info" {
    const std = @import("std");

    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    const info = @This(){
        .versions = &.{ .U2F_V2, .FIDO_2_0, .FIDO_2_1_PRE },
        .aaguid = "\x2f\xc0\x57\x9f\x81\x13\x47\xea\xb1\x16\xbb\x5a\x8d\xb9\x20\x2a".*,
        .options = .{ .rk = true, .up = true, .plat = false, .clientPin = true },
        .max_msg_size = 1200,
        .pin_uv_auth_protocols = &.{ .v2, .v1 },
        .max_credential_count_id_list = 8,
        .max_credential_id_length = 128,
        .transports = &.{ .nfc, .usb },
        .algorithms = &.{ .{ .alg = .Es256 }, .{ .alg = .EdDsa } },
        .min_pin_length = 4,
        .firmware_version = 328707,
    };

    try cbor.stringify(info, .{}, str.writer());

    try std.testing.expectEqualSlices(u8, "\xab\x01\x83\x66\x55\x32\x46\x5f\x56\x32\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30\x6c\x46\x49\x44\x4f\x5f\x32\x5f\x31\x5f\x50\x52\x45\x03\x50\x2f\xc0\x57\x9f\x81\x13\x47\xea\xb1\x16\xbb\x5a\x8d\xb9\x20\x2a\x04\xa6\x62\x72\x6b\xf5\x62\x75\x70\xf5\x64\x70\x6c\x61\x74\xf4\x69\x63\x6c\x69\x65\x6e\x74\x50\x69\x6e\xf5\x70\x6d\x61\x6b\x65\x43\x72\x65\x64\x55\x76\x4e\x6f\x74\x52\x71\x64\xf4\x78\x1e\x6e\x6f\x4d\x63\x47\x61\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x73\x57\x69\x74\x68\x43\x6c\x69\x65\x6e\x74\x50\x69\x6e\xf4\x05\x19\x04\xb0\x06\x82\x02\x01\x07\x08\x08\x18\x80\x09\x82\x63\x6e\x66\x63\x63\x75\x73\x62\x0a\x82\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\xa2\x63\x61\x6c\x67\x27\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x0d\x04\x0e\x1a\x00\x05\x04\x03", str.items);
}
