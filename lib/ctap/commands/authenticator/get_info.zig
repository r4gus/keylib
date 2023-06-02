const cbor = @import("zbor");
const fido = @import("../../../main.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn authenticatorGetInfo(settings: fido.ctap.authenticator.Settings, out: anytype) !void {
    try cbor.stringify(settings, .{}, out);
}
