const fido = @import("../../main.zig");
const cbor = @import("zbor");

/// This registration extension allows relying parties to specify a credential
/// protection policy when creating a credential.
credProtect: ?fido.ctap.extensions.CredentialCreationPolicy = null,

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    return cbor.stringify(self, .{
        .allocator = options.allocator,
        .from_cborStringify = true,
        .field_settings = &.{
            .{ .name = "credProtect", .options = .{ .enum_as_text = false } },
        },
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "credProtect", .options = .{} },
        },
    });
}
