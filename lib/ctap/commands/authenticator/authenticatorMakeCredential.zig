const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

pub fn authenticatorMakeCredential(
    auth: *fido.ctap.authenticator.Authenticator,
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
    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (mcp.pubKeyCredParams) |param| outer_alg: {
        for (auth.algorithms) |algorithm| {
            if (param.alg == algorithm.alg) {
                alg = algorithm;
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

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_supported = false;
    var rk_supported = false;

    if (auth.settings.options) |options| {
        if (options.uv != null and options.uv.? and auth.callbacks.uv != null) {
            uv_supported = true;
        }

        if (options.rk and auth.callbacks.load_resident_key != null and auth.callbacks.store_resident_key != null) {
            rk_supported = true;
        }
    }

    var uv: bool = if (mcp.options != null and mcp.options.?.uv != null) mcp.options.?.uv.? else false;
    uv = if (mcp.pinUvAuthParam != null) false else uv;

    if (uv and !uv_supported) {
        // If the authenticator does not support a built-in user verification
        // method end the operation by returning CTAP2_ERR_INVALID_OPTION
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const rk: bool = if (mcp.options != null and mcp.options.?.rk != null) mcp.options.?.rk.? else false;

    if (rk and !rk_supported) {
        // If the rk option ID is not present in authenticatorGetInfo response,
        // end the operation by returning CTAP2_ERR_UNSUPPORTED_OPTION.
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
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
        for (ecllist) |ecl| {
            // Try to load the credential with the given id. If
            // this fails then just continue with the next possible id.
            const _cred = auth.callbacks.load_credential_by_id(
                ecl.id,
                auth.allocator,
            ) catch {
                continue;
            };
            defer auth.allocator.free(_cred);
            var di = cbor.DataItem.new(_cred) catch {
                continue;
            };
            const cred = cbor.parse(
                fido.ctap.authenticator.Credential,
                di,
                .{ .allocator = auth.allocator },
            ) catch {
                // TODO: This should not fail but who knows...
                continue;
            };
            cred.deinit(auth.allocator);

            if (cred.policy != .userVerificationRequired) {
                var userPresentFlagValue = false;
                if (mcp.pinUvAuthParam) |_| {
                    var token = switch (mcp.pinUvAuthProtocol.?) {
                        .V1 => &auth.token.one.?,
                        .V2 => &auth.token.two.?,
                    };
                    userPresentFlagValue = token.getUserPresentFlagValue();
                } else {
                    userPresentFlagValue = up_response;
                }

                if (!userPresentFlagValue) {
                    _ = auth.callbacks.up(null, null);
                    return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                }
            } else {
                if (uv_response) {
                    var userPresentFlagValue = false;
                    if (mcp.pinUvAuthParam) |_| {
                        var token = switch (mcp.pinUvAuthProtocol.?) {
                            .V1 => &auth.token.one.?,
                            .V2 => &auth.token.two.?,
                        };
                        userPresentFlagValue = token.getUserPresentFlagValue();
                    } else {
                        userPresentFlagValue = up_response;
                    }

                    if (!userPresentFlagValue) {
                        _ = auth.callbacks.up(null, null);
                        return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                    } else {
                        return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                    }
                } else {
                    // (implying user verification was not collected in Step 11),
                    // remove the credential from the excludeList and continue parsing
                    // the rest of the list.
                    continue;
                }
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 13. TODO
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 14. Check user presence
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (up) {
        if (mcp.pinUvAuthParam != null) {
            var token = switch (mcp.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };
            if (!token.getUserPresentFlagValue()) {
                if (auth.callbacks.up(&mcp.user, &mcp.rp) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up(&mcp.user, &mcp.rp) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        }

        up_response = true;

        if (mcp.pinUvAuthProtocol) |prot| {
            var token = switch (prot) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };
            token.clearUserPresentFlag();
            token.clearUserVerifiedFlag();
            token.clearPinUvAuthTokenPermissionsExceptLbw();
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 15. Process extensions
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    // We go with the weakest policy, if one wants to use a higher policy then she can
    // always provide the `credProtect` extension.
    var policy = fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
    var cred_random: ?struct {
        CredRandomWithUV: [32]u8,
        CredRandomWithoutUV: [32]u8,
    } = null;
    var extensions: ?fido.ctap.extensions.Extensions = null;

    if (auth.extensionSupported(.@"hmac-secret")) {
        // The authenticator generates two random 32-byte values (called CredRandomWithUV
        // and CredRandomWithoutUV) and associates them with the credential.
        cred_random = undefined;
        auth.callbacks.rand.bytes(cred_random.?.CredRandomWithUV[0..]);
        auth.callbacks.rand.bytes(cred_random.?.CredRandomWithoutUV[0..]);
    }

    if (mcp.extensions) |ext| {
        // Set the requested policy
        if (ext.credProtect) |pol| {
            policy = pol;

            if (extensions) |*exts| {
                exts.credProtect = pol;
            } else {
                extensions = fido.ctap.extensions.Extensions{
                    .credProtect = pol,
                };
            }
        }

        // Prepare hmac-secret
        if (ext.@"hmac-secret") |hsec| {
            switch (hsec) {
                .create => |flag| {
                    // The creation of the two random values will always succeed,
                    // so we'll always return true.
                    if (flag) {
                        if (extensions) |*exts| {
                            exts.@"hmac-secret" = .{ .create = true };
                        } else {
                            extensions = fido.ctap.extensions.Extensions{
                                .@"hmac-secret" = .{ .create = true },
                            };
                        }
                    }
                },
                else => {},
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 16. Create a new credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    const key_pair = if (alg.?.create(
        auth.callbacks.rand,
        auth.allocator,
    )) |kp| kp else return fido.ctap.StatusCodes.ctap1_err_other;
    defer {
        auth.allocator.free(key_pair.cose_public_key);
        auth.allocator.free(key_pair.raw_private_key);
    }

    var credential = fido.ctap.authenticator.Credential{
        .id = undefined,
        .rpId = mcp.rp.id,
        .user = mcp.user,
        .policy = policy,
        .signCtr = 1, // this includes the first signature possibly made below
        .time_stamp = @intCast(u64, auth.callbacks.millis()),
        .key = .{
            .raw = key_pair.raw_private_key,
            .alg = alg.?.alg,
        },
    };
    if (cred_random) |cr| {
        credential.cred_random = undefined;
        credential.cred_random.?.CredRandomWithUV = cr.CredRandomWithUV;
        credential.cred_random.?.CredRandomWithoutUV = cr.CredRandomWithoutUV;
    }
    // TODO: verify that the id is unique
    auth.callbacks.rand.bytes(&credential.id);

    var serialized_cred = std.ArrayList(u8).init(auth.allocator);
    cbor.stringify(
        &credential,
        .{},
        serialized_cred.writer(),
    ) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer serialized_cred.deinit();

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 17. + 18. Store credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    if (rk) {
        // We (the authenticator) MUST create a discoverable credential
        //
        // NOTE: We've already checked in 5. that the callbacks are provided
        auth.callbacks.store_resident_key.?(
            mcp.rp.id,
            mcp.user.id,
            serialized_cred.items,
        ) catch |e| {
            switch (e) {
                error.KeyStoreFull => return fido.ctap.StatusCodes.ctap2_err_key_store_full,
            }
        };
    } else {
        // Create a non-discoverable credential
        auth.callbacks.store_credential_by_id(
            &credential.id,
            serialized_cred.items,
        );
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 19. Create attestation statement
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var auth_data = fido.common.AuthenticatorData{
        .rpIdHash = undefined,
        .flags = .{
            .up = if (up_response) 1 else 0,
            .rfu1 = 0,
            .uv = if (uv_response) 1 else 0,
            .rfu2 = 0,
            .at = 1,
            .ed = 0,
        },
        .signCount = 0,
        .attestedCredentialData = .{
            .aaguid = auth.settings.aaguid,
            .credential_length = credential.id[0..].len,
            .credential_id = credential.id[0..],
            .credential_public_key = key_pair.cose_public_key,
        },
        .extensions = extensions,
    };
    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        mcp.rp.id,
        &auth_data.rpIdHash,
        .{},
    );

    const stmt = switch (auth.attestation_type) {
        .Self => blk: {
            var authData = std.ArrayList(u8).init(auth.allocator);
            defer authData.deinit();
            try auth_data.encode(authData.writer());

            const sig = alg.?.sign(
                key_pair.raw_private_key,
                &.{
                    authData.items,
                    &mcp.clientDataHash,
                },
                auth.allocator,
            ).?;

            break :blk fido.common.AttestationStatement{ .@"packed" = .{
                .alg = alg.?.alg,
                .sig = sig,
            } };
        },
        else => blk: {
            break :blk fido.common.AttestationStatement{
                .none = .{},
            };
        },
    };

    const ao = fido.ctap.response.MakeCredential{
        .fmt = fido.common.AttestationStatementFormatIdentifiers.@"packed",
        .authData = auth_data,
        .attStmt = stmt,
    };

    cbor.stringify(ao, .{ .allocator = auth.allocator }, out) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    status = fido.ctap.StatusCodes.ctap1_err_success;
    return status;
}
