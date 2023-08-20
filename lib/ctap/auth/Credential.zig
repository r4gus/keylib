const std = @import("std");
const fido = @import("../../../main.zig");
const cbor = @import("zbor");

/// Credential ID
_id: ?[]const u8 = null,

/// Revision (can be ignored for the most part)
_rev: ?[]const u8 = null,

/// Information about the user the credential belongs to (including the user ID)
user: fido.common.User,

/// The ID of the Relying Party (usually a base URL)
rp_id: []const u8,

/// Number of signatures issued using the given credential
sign_count: u64,

/// Signature algorithm to use for the credential
alg: cbor.cose.Algorithm,

/// The encrypted private key
private_key: []const u8,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self._id) |id| {
        allocator.free(id);
    }
    if (self._rev) |rev| {
        allocator.free(rev);
    }
    self.user.deinit(allocator);
    allocator.free(self.rp_id);
    allocator.free(self.private_key);
}
