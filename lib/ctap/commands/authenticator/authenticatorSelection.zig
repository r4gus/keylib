const fido = @import("../../../main.zig");

pub fn authenticatorSelection(
    auth: *fido.ctap.authenticator.Authenticator,
) fido.ctap.StatusCodes {
    const up = auth.callbacks.up(null, null);

    return switch (up) {
        .Denied => fido.ctap.StatusCodes.ctap2_err_operation_denied,
        .Accepted => fido.ctap.StatusCodes.ctap1_err_success,
        .Timeout => fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
    };
}
