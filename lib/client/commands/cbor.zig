const root = @import("../../main.zig");
const data = root.data;

const cbor = @import("zbor");

const device = @import("../device.zig");

// ++++++++++++++++++++++++++++++++++++++
// authenticatorGetInfo
// ++++++++++++++++++++++++++++++++++++++

pub fn authenticatorGetInfo(auth: *device.Authenticator) !data.Settings {
    try auth.write("\x04");
    const response = try auth.read();
    defer auth.transport.allocator.free(response);

    const info = try cbor.parse(
        data.Settings,
        try cbor.DataItem.new(response[1..]),
        .{
            .allocator = auth.transport.allocator,
            .field_settings = &.{
                .{ .name = "versions", .alias = "1", .options = .{} },
                .{ .name = "extensions", .alias = "2", .options = .{} },
                .{ .name = "aaguid", .alias = "3", .options = .{} },
                .{ .name = "options", .alias = "4", .options = .{} },
                .{ .name = "max_msg_size", .alias = "5", .options = .{} },
                .{ .name = "pin_uv_auth_protocols", .alias = "6", .options = .{ .enum_as_text = false } },
                .{ .name = "max_credential_count_id_list", .alias = "7", .options = .{} },
                .{ .name = "max_credential_id_length", .alias = "8", .options = .{} },
                .{ .name = "transports", .alias = "9", .options = .{} },
                .{ .name = "algorithms", .alias = "10", .options = .{ .enum_as_text = false } },
                .{ .name = "max_serialized_large_blob_array", .alias = "11", .options = .{} },
                .{ .name = "force_pin_change", .alias = "12", .options = .{} },
                .{ .name = "min_pin_length", .alias = "13", .options = .{} },
                .{ .name = "firmware_version", .alias = "14", .options = .{} },
                .{ .name = "max_cred_blob_length", .alias = "15", .options = .{} },
                .{ .name = "max_prids_for_set_min_pin_length", .alias = "16", .options = .{} },
                .{ .name = "preferred_platform_uv_attempts", .alias = "17", .options = .{} },
                .{ .name = "uv_modality", .alias = "18", .options = .{} },
                .{ .name = "certifications", .alias = "19", .options = .{} },
                .{ .name = "remaining_discoverable_credentials", .alias = "20", .options = .{} },
                .{ .name = "vendor_prototype_config_commands", .alias = "21", .options = .{} },
            },
        },
    );

    return info;
}
