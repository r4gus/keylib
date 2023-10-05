const std = @import("std");
const fido = @import("../../../main.zig");

/// Verify that the pinUvAuthToken support matches the given parameter
///
/// This covers 1. and 2. of GetAssertion and MakeCredential
///
/// Returns CTAP_ERR_SUCCESS if everything is ok
pub fn verifyPinUvAuthParam(
    auth: *const fido.ctap.authenticator.Auth,
    param: anytype,
) fido.ctap.StatusCodes {
    if (param.pinUvAuthParam != null) {
        if (param.pinUvAuthProtocol == null) {
            return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
        } else if (param.pinUvAuthProtocol.? != auth.token.version) {
            return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
        }
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}
