const std = @import("std");

const PublicKeyCredentialDescriptor = @import("../PublicKeyCredentialDescriptor.zig");
const AuthenticatorOptions = @import("../AuthenticatorOptions.zig");
const PinProtocol = @import("../client_pin/pin_protocol.zig").PinProtocol;

/// Relying party identifier.
rpId: [:0]const u8, // 1
/// Hash of the serialized client data collected by the host.
clientDataHash: []const u8, // 2
/// A sequence of PublicKeyCredentialDescriptor structures, each
/// denoting a credential, as specified in [WebAuthN]. If this parameter is
/// present and has 1 or more entries, the authenticator MUST only generate
/// an assertion using one of the denoted credentials.
allowList: ?[]const PublicKeyCredentialDescriptor = null, // 3
// TODO: add remaining fields (extensions 0x4)
/// Parameters to influence authenticator operation.
options: ?AuthenticatorOptions = null, // 5
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?[32]u8 = null, // 6
/// PIN protocol version selected by client.
pinUvAuthProtocol: ?PinProtocol = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.rpId);
    allocator.free(self.clientDataHash);
    if (self.allowList) |pkcds| {
        for (pkcds) |pkcd| {
            pkcd.deinit(allocator);
        }
        allocator.free(pkcds);
    }
}
