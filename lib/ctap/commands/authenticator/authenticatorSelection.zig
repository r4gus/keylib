const fido = @import("../../../main.zig");

pub fn authenticatorSelection(
    auth: *fido.ctap.authenticator.Authenticator,
) fido.ctap.StatusCodes {
    if (auth.callbacks.up(null, null)) {
        return fido.ctap.StatusCodes.ctap1_err_success;
    } else {
        return fido.ctap.StatusCodes.ctap2_err_operation_denied;
    }
}
