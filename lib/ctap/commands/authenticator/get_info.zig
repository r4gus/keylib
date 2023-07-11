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
    var settings = if (auth.callbacks.getEntry("Settings")) |settings| settings else {
        std.log.err("Unable to fetch Settings", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    // Check if we have set a pin
    if (settings.getField("Pin", auth.callbacks.millis())) |_| {
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

    if (settings.getField("ForcePinChange", auth.callbacks.millis())) |fpc| {
        if (std.mem.eql(u8, fpc, "True")) {
            auth.settings.forcePINChange = true;
        } else {
            auth.settings.forcePINChange = false;
        }
    } else {
        auth.settings.forcePINChange = null;
    }

    if (settings.getField("MinPinLength", auth.callbacks.millis())) |mpl| {
        std.debug.print("minPinLength: {d}\n", .{mpl[0]});
        auth.settings.minPINLength = mpl[0];
    }

    if (settings.getField("AlwaysUv", auth.callbacks.millis())) |auv| {
        if (std.mem.eql(u8, auv, "True")) {
            auth.settings.options.?.alwaysUv = true;
        } else {
            auth.settings.options.?.alwaysUv = false;
        }
    } else {
        auth.settings.options.?.alwaysUv = null;
    }

    try cbor.stringify(auth.settings, .{}, out);

    return fido.ctap.StatusCodes.ctap1_err_success;
}
