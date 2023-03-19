const std = @import("std");
const cbor = @import("zbor");
const data = @import("../data.zig");

const Authenticator = @import("../Authenticator.zig");
const PinProtocol = data.client_pin.PinProtocol;
const PinUvAuthParam = @import("../crypto.zig").pin.PinUvAuthParam;
const MakeCredentialParam = data.make_credential.MakeCredentialParam;

pub fn verify_make_credential(
    auth: *Authenticator,
    make_credential_param: *const MakeCredentialParam,
) !data.StatusCodes {
    // Return error if the authenticator does not receive the
    // mandatory parameters for this command.
    if (make_credential_param.pinUvAuthProtocol == null) {
        return data.StatusCodes.ctap2_err_missing_parameter;
    }

    // Return error if a zero length pinUvAuthParam is receieved
    if (make_credential_param.pinUvAuthParam == null) {
        if (!auth.resources.request_permission(
            &make_credential_param.user,
            &make_credential_param.rp,
        )) {
            return data.StatusCodes.ctap2_err_operation_denied;
        } else {
            return data.StatusCodes.ctap2_err_pin_invalid;
        }
    }

    return verify(
        auth,
        make_credential_param.pinUvAuthProtocol.?,
        make_credential_param.pinUvAuthParam.?,
        make_credential_param.clientDataHash,
        make_credential_param.rp.id,
        0x01,
    );
}

pub fn verify(
    auth: *Authenticator,
    protocol: PinProtocol,
    param: PinUvAuthParam,
    clientDataHash: []const u8,
    rpId: []const u8,
    permission_flags: u8,
) !data.StatusCodes {
    // If pinUvAuthProtocol is not supported, return error.
    var protocol_supported: bool = false;
    for (auth.settings.pin_uv_auth_protocols) |prot| {
        if (prot == protocol) {
            protocol_supported = true;
            break;
        }
    }

    if (!protocol_supported) {
        return data.StatusCodes.ctap1_err_invalid_parameter;
    }

    // Enforce user verification
    if (!auth.state.in_use) { // TODO: maybe just switch with getUserVerifiedFlagValue() call
        return data.StatusCodes.ctap2_err_pin_token_expired;
    }

    if (!data.State.verify(
        auth.state.pin_token,
        clientDataHash,
        param,
    )) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    if (auth.state.permissions & permission_flags == 0) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    if (auth.state.rp_id) |rp_id| {
        if (!std.mem.eql(u8, rpId, rp_id)) {
            return data.StatusCodes.ctap2_err_pin_auth_invalid;
        }
    }

    if (!auth.state.getUserVerifiedFlagValue()) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    // TODO: If the pinUvAuthToken does not have a permissions RP ID associated:
    // Associate the request’s rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
    return data.StatusCodes.ctap1_err_success;
}
