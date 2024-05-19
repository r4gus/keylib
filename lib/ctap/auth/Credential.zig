const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");

/// Credential ID
id: []const u8,

/// User information
user: fido.common.User,

/// Information about the relying party
rp: fido.common.RelyingParty,

/// Number of signatures issued using the given credential
sign_count: u64,

/// Signature algorithm to use for the credential
alg: cbor.cose.Algorithm,

/// Private key
private_key: []const u8 = undefined,

/// Epoch time stamp this credential was created
created: i64,

/// Is this credential discoverable or not
///
/// This is kind of stupid but authenticatorMakeCredential
/// docs state, that you're not allowed to create a discoverable
/// credential if not explicitely requested. The docs also state
/// that you're allowed to keep (some) state, e.g., store the key.
discoverable: bool = false,

extensions: ?[]ExtensionTuple = null,

//policy: fido.ctap.extensions.CredentialCreationPolicy = .userVerificationOptional,
//
///// Belongs to hmac secret
//cred_random_with_uv: [32]u8 = undefined,
//
///// Belongs to hmac secret
//cred_random_without_uv: [32]u8 = undefined,

pub fn getExtensions(self: *const @This(), id: []const u8) ?[]const u8 {
    if (self.extensions == null) return null;

    for (self.extensions.?) |ext| {
        if (std.mem.eql(u8, id, ext.extId)) {
            return ext.extValue;
        }
    }
    return null;
}

pub fn setExtension(
    self: *@This(),
    id: []const u8,
    value: []const u8,
    a: std.mem.Allocator,
) !void {
    if (self.extensions == null) {
        self.extensions = try a.alloc(ExtensionTuple, 1);
    } else {
        self.extensions = try a.realloc(self.extensions.?, self.extensions.?.len + 1);
    }

    for (self.extensions.?) |*ext| {
        if (std.mem.eql(u8, id, ext.extId)) {
            a.free(ext.extValue);
            ext.extValue = try a.dupe(u8, value);
            return;
        }
    }

    self.extensions.?[self.extensions.?.len - 1] = .{
        .extId = try a.dupe(u8, id),
        .extValue = try a.dupe(u8, value),
    };
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.private_key);
    if (self.extensions) |extensions| {
        for (extensions) |extension| {
            allocator.free(extension.extId);
            allocator.free(extension.extValue);
        }
        allocator.free(extensions);
    }
}

pub fn desc(_: void, lhs: @This(), rhs: @This()) bool {
    return lhs.created > rhs.created;
}

pub const ExtensionTuple = struct {
    extId: []u8,
    extValue: []u8,
};
