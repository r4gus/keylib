//! Contains the attributes that are specified by a caller when referring to a public key credential.
//! See WebAuthn §5.8.3.

/// The credential id
id: []const u8,
/// Type of the credential
type: []const u8,
/// Transport methods
transports: ?[]const [:0]const u8 = null,

/// Free all allocated memory of this data structure
pub fn deinit(self: *const @This(), allocator: @import("std").mem.Allocator) void {
    allocator.free(self.type);
    allocator.free(self.id);
    if (self.transports) |trans| {
        for (trans) |t| {
            allocator.free(t);
        }
        allocator.free(trans);
    }
}
