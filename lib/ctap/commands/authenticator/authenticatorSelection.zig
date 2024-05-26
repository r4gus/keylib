const std = @import("std");
const fido = @import("../../../main.zig");

pub fn authenticatorSelection(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    _ = request;
    _ = out;

    const up = auth.callbacks.up(
        "Use this authenticator?",
        null,
        null,
    );

    return switch (up) {
        .Denied => fido.ctap.StatusCodes.ctap2_err_operation_denied,
        .Accepted => fido.ctap.StatusCodes.ctap1_err_success,
        .Timeout => fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
    };
}
