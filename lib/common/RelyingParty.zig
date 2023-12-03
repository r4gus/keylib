//! Representation of a relying party

const cbor = @import("zbor");

/// Relying party identifier
///
/// A relying party identifier is a valid domain string identifying the WebAuthn
/// Relying Party on whose behalf a given registration or authentication ceremony
/// is being performed.
id: []const u8,
/// Name of the relying party
name: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: @import("std").mem.Allocator) void {
    allocator.free(self.id);
    if (self.name) |name| {
        allocator.free(name);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "id", .value_options = .{ .slice_serialization_type = .TextString } },
            .{ .name = "name", .value_options = .{ .slice_serialization_type = .TextString } },
        },
        .from_callback = true,
    }, out);
}
