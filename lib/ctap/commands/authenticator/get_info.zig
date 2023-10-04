const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn authenticatorGetInfo(
    auth: *fido.ctap.authenticator.Auth,
    out: anytype,
) !fido.ctap.StatusCodes {
    try cbor.stringify(auth.settings, .{}, out);
    return fido.ctap.StatusCodes.ctap1_err_success;
}
