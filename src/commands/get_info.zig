const cbor = @import("zbor");
const data = @import("../data.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn get_info(settings: data.Settings, out: anytype) !void {
    try cbor.stringify(settings, .{}, out);
}
