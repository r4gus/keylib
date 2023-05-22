const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

pub fn authenticatorMakeCredential(
    auth: *fido.ctap.authenticator.Authenticator,
    mcp: *const fido.ctap.request.MakeCredential,
    out: anytype,
) !fido.ctap.StatusCodes {
    _ = out;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var status = helper.verifyPinUvAuthParam(auth, mcp);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. Validate pubKeyCredParams
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var alg: ?cbor.cose.Algorithm = null;
    for (mcp.pubKeyCredParams) |param| outer_alg: {
        for (auth.settings.algorithms) |algorithm| {
            if (param.alg == algorithm.alg) {
                alg = algorithm.alg;
                break :outer_alg;
            }
        }
    }

    if (alg == null) {
        return fido.ctap.StatusCodes.ctap2_err_unsupported_algorithm;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_response = false;
    var up_response = false;
    _ = up_response;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv: bool = if (mcp.options != null and mcp.options.?.uv != null) mcp.options.?.uv.? else false;
    uv = if (mcp.pinUvAuthParam != null) false else uv;
    if (uv and auth.callbacks.uv == null) {
        // If the authenticator does not support a built-in user verification
        // method end the operation by returning CTAP2_ERR_INVALID_OPTION
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const rk: bool = if (mcp.options != null and mcp.options.?.rk != null) mcp.options.?.rk.? else false;
    if (auth.settings.options) |options| {
        if (!options.rk and rk) {
            // If the rk option ID is not present in authenticatorGetInfo response,
            // end the operation by returning CTAP2_ERR_UNSUPPORTED_OPTION.
            return fido.ctap.StatusCodes.ctap2_err_invalid_option;
        }
    }

    const up: bool = if (mcp.options != null and mcp.options.?.up != null) mcp.options.?.up.? else true;
    if (!up) {
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Validate alwaysUv
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const alwaysUv = if (auth.settings.options != null and auth.settings.options.?.alwaysUv != null) auth.settings.options.?.alwaysUv.? else false;
    var makeCredUvNotRqd = if (auth.settings.options != null) auth.settings.options.?.makeCredUvNotRqd else false;
    const noMcGaPermissionsWithClientPin = if (auth.settings.options != null) auth.settings.options.?.noMcGaPermissionsWithClientPin else false;
    if (alwaysUv) {
        makeCredUvNotRqd = false;

        const is_protected = if (auth.callbacks.uv != null or auth.token.one != null or auth.token.two != null) true else false;
        if (!is_protected) {
            // TODO: look over this once more!
            return fido.ctap.StatusCodes.ctap2_err_operation_denied;
        }

        if (mcp.pinUvAuthParam == null and auth.callbacks.uv != null) {
            // If the pinUvAuthParam is not present, and the uv option ID is true,
            // let the "uv" option be treated as being present with the value true.
            uv = true;
        }

        if (mcp.pinUvAuthParam == null and !uv) {
            if ((auth.token.one != null or auth.token.two != null) and !noMcGaPermissionsWithClientPin) {
                return fido.ctap.StatusCodes.ctap2_err_pin_required;
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 7. and 8. Validate makeCredUvNotRqd
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (makeCredUvNotRqd) {
        // This step returns an error if the platform tries to create a discoverable
        // credential without performing some form of user verification.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null and rk) {
            if (auth.getClientPinOption() and !noMcGaPermissionsWithClientPin) {
                return fido.ctap.StatusCodes.ctap2_err_pin_required;
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }
    } else {
        // This step returns an error if the platform tries to create a credential
        // without performing some form of user verification when the makeCredUvNotRqd
        // option ID in authenticatorGetInfo's response is present with the value
        // false or is absent.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null) {
            if (auth.getClientPinOption() and !noMcGaPermissionsWithClientPin) {
                return fido.ctap.StatusCodes.ctap2_err_pin_required;
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 9. Validate enterpriseAttestation
    //
    // WE ARE CURRENTLY NOT ENTERPRISE ATTESTATION CAPABLE!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (mcp.enterpriseAttestation) |ea| {
        _ = ea;
        return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 10. Check if non-discoverable credential creation
    //     is allowed
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    const skip_auth = if ((!rk and !uv) and makeCredUvNotRqd and mcp.pinUvAuthParam == null) true else false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. Verify user (skip if skip_auth == true)
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (!skip_auth) {
        if (mcp.pinUvAuthParam) |puap| {
            var pinuvprot = switch (mcp.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            if (!pinuvprot.verify_token(&mcp.clientDataHash, &puap, auth.allocator)) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (pinuvprot.permissions & 0x01 == 0) {
                // Check if mc permission is set
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (pinuvprot.rp_id) |rp_id| {
                // Match rpIds if possible
                if (!std.mem.eql(u8, mcp.rp.id, rp_id)) {
                    // Ids don't match
                    return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
                }
            }

            if (!pinuvprot.getUserVerifiedFlagValue()) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            } else {
                uv_response = true;
            }

            // associate the rpId with the token
            if (pinuvprot.rp_id == null) {
                pinuvprot.setRpId(mcp.rp.id);
            }
        } else if (uv) {
            // TODO: performBuiltInUv(internalRetry)
            return fido.ctap.StatusCodes.ctap2_err_uv_invalid;
        } else {
            // This should be unreachable but we'll return an error
            // just in case.
            return fido.ctap.StatusCodes.ctap1_err_other;
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 12. Check exclude list
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (mcp.excludeList) |ecllist| {
        _ = ecllist;
    }

    return status;
}
