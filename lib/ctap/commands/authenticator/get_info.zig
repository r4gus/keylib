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

    try cbor.stringify(auth.settings, .{}, out);

    return fido.ctap.StatusCodes.ctap1_err_success;
}
