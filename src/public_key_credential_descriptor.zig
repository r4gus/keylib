// https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor

const std = @import("std");

/// Contains the attributes that are specified by a caller when referring to a
/// public key credential.
///
/// See WebAuthn §5.8.3.
pub const PublicKeyCredentialDescriptor = struct {
    @"type": []const u8,
    id: []const u8,
    transports: ?[]const []const u8,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.@"type");
        allocator.free(self.id);
        if (self.transports) |trans| {
            for (trans) |t| {
                allocator.free(t);
            }
            allocator.free(trans);
        }
    }
};
