const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn authenticatorGetInfo(
    auth: *fido.ctap.authenticator.Auth,
    out: anytype,
) !fido.ctap.StatusCodes {
    const settings = auth.loadSettings() catch |e| {
        std.log.err("authenticatorGetInfo: unable to load settings", .{});
        return e;
    };

    auth.settings.minPINLength = settings.min_pin_length;
    auth.settings.forcePINChange = settings.force_pin_change;
    auth.settings.options.alwaysUv = settings.always_uv;

    try cbor.stringify(auth.settings, .{}, out);
    return fido.ctap.StatusCodes.ctap1_err_success;
}
