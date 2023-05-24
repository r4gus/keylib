//! Representation of a relying party

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
