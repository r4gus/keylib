const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn authenticatorGetInfo(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
) !fido.ctap.StatusCodes {
    // Fetch dynamic settings, these will override the static settings set
    // during instantiation.
    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("authenticatorGetAssertion: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("authenticatorGetAssertion: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // Check if we have set a pin
    if (settings.pin != null) {
        // null means no client pin support => we wont change that!
        if (auth.settings.options.?.clientPin != null) {
            auth.settings.options.?.clientPin = true;
        }
    } else {
        // null means no client pin support => we wont change that!
        if (auth.settings.options.?.clientPin != null) {
            auth.settings.options.?.clientPin = false;
        }
    }

    if (settings.force_pin_change) {
        auth.settings.forcePINChange = true;
    } else {
        auth.settings.forcePINChange = false;
    }

    auth.settings.minPINLength = settings.min_pin_length;

    if (settings.always_uv) {
        auth.settings.options.?.alwaysUv = true;
    } else {
        auth.settings.options.?.alwaysUv = false;
    }

    try cbor.stringify(auth.settings, .{}, out);

    return fido.ctap.StatusCodes.ctap1_err_success;
}
