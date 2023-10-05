const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const uuid = @import("uuid");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

const deriveMacKey = fido.ctap.crypto.master_secret.deriveMacKey;
const deriveEncKey = fido.ctap.crypto.master_secret.deriveEncKey;

pub fn authenticatorMakeCredential(
    auth: *fido.ctap.authenticator.Auth,
    mcp: *const fido.ctap.request.MakeCredential,
    out: anytype,
) !fido.ctap.StatusCodes {
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var status = helper.verifyPinUvAuthParam(auth, mcp);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. Validate pubKeyCredParams
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var alg = if (auth.selectSignatureAlgorithm(mcp.pubKeyCredParams)) |alg| alg else {
        return fido.ctap.StatusCodes.ctap2_err_unsupported_algorithm;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_response = false;
    var up_response = false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_supported = auth.uvSupported();
    var rk_supported = auth.rkSupported();

    var uv = mcp.requestsUv();
    uv = if (mcp.pinUvAuthParam != null) false else uv; // pin overwrites uv
    if (uv and !uv_supported) {
        // If the authenticator does not support a built-in user verification
        // method end the operation by returning CTAP2_ERR_INVALID_OPTION
        std.log.err("makeCredential: uv ({any}) requested by client but not supported", .{auth.token.version});
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const rk = mcp.requestsRk();
    if (rk and !rk_supported) {
        // If the rk option ID is not present in authenticatorGetInfo response,
        // end the operation by returning CTAP2_ERR_UNSUPPORTED_OPTION.
        std.log.err("makeCredential: rk requested by client but not supported", .{});
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const up = mcp.requestsUp();
    if (!up) {
        std.log.err("makeCredential: up = false not allowed", .{});
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Validate alwaysUv
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const alwaysUv = try auth.alwaysUv();
    var makeCredUvNotRqd = auth.makeCredUvNotRqd();
    const noMcGaPermissionsWithClientPin = auth.noMcGaPermissionsWithClientPin();

    if (alwaysUv) {
        // alwaysUv overwrites makeCredUvNotRqd
        makeCredUvNotRqd = false;

        const is_protected = auth.isProtected();

        if (!is_protected) {
            std.log.err("makeCredential: alwaysUv = true but not protected", .{});
            // This handles the case that clientPin is supported in general
            // but not configured yet.
            if (auth.clientPinSupported()) |_| {
                if (!noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }

        if (mcp.pinUvAuthParam == null and auth.uvSupported()) {
            // If the pinUvAuthParam is not present, and the uv option ID is true,
            // let the "uv" option be treated as being present with the value true.
            uv = true;
        }

        if (mcp.pinUvAuthParam == null and !uv) {
            std.log.err("makeCredential: alwaysUv = true but not protected", .{});
            if (auth.clientPinSupported()) |_| {
                if (!noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 7. and 8. Validate makeCredUvNotRqd
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (makeCredUvNotRqd) {
        std.log.err("makeCredential: uv required for resident key", .{});
        // This step returns an error if the platform tries to create a discoverable
        // credential without performing some form of user verification.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null and rk) {
            if (auth.clientPinSupported()) |supported| {
                if (supported and !noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            }
            return fido.ctap.StatusCodes.ctap2_err_operation_denied;
        }
    } else {
        std.log.err("makeCredential: requires user verification but uv = false and pinUvAuthParam not present", .{});
        // This step returns an error if the platform tries to create a credential
        // without performing some form of user verification when the makeCredUvNotRqd
        // option ID in authenticatorGetInfo's response is present with the value
        // false or is absent.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null) {
            if (auth.clientPinSupported()) |supported| {
                if (supported and !noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            }
            return fido.ctap.StatusCodes.ctap2_err_operation_denied;
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 9. Validate enterpriseAttestation
    //
    // WE ARE CURRENTLY NOT ENTERPRISE ATTESTATION CAPABLE!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (mcp.enterpriseAttestation) |ea| {
        std.log.err("makeCredential: enterprise attestation not supported", .{});
        _ = ea;
        return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 10. Check if non-discoverable credential creation
    //     is allowed
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const skip_auth = (!rk and !uv and makeCredUvNotRqd and mcp.pinUvAuthParam == null);

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. Verify user (skip if skip_auth == true)
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (!skip_auth) {
        if (mcp.pinUvAuthParam) |_| {
            // TODO: this is currently not supported and should be
            // unreachable.
            return fido.ctap.StatusCodes.ctap2_err_uv_invalid;
        } else if (uv) {
            const uvState = auth.token.performBuiltInUv(true, auth);
            switch (uvState) {
                .Blocked => return fido.ctap.StatusCodes.ctap2_err_pin_blocked,
                .Timeout => return fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
                .Denied => {
                    if (auth.clientPinSupported()) |supported| {
                        if (supported and !noMcGaPermissionsWithClientPin) {
                            return fido.ctap.StatusCodes.ctap2_err_pin_required;
                        }
                    }
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                },
                .Accepted => {
                    uv_response = true;
                },
            }
        } else {
            // This should be unreachable but we'll return an error
            // just in case.
            return fido.ctap.StatusCodes.ctap1_err_other;
        }
    }

    // If this step was skiped, then the authenticator is NOT protected by some form of
    // user verification, and step 4 has already ensured that the "uv" (uv_response) bit is false

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 12. Check exclude list
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    _ = up_response;
    _ = alg;
    _ = out;

    return status;
}
