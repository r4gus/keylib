const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const uuid = @import("uuid");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");
const deriveMacKey = fido.ctap.crypto.master_secret.deriveMacKey;
const deriveEncKey = fido.ctap.crypto.master_secret.deriveEncKey;

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

        if (options.rk) {
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

    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("authenticatorMakeCredential: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer settings.deinit(auth.allocator);
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("authenticatorMakeCredential: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const ms = try settings.getSecret(auth.secret.enc);

    // The authenticator returns an error if the authenticator already contains one of the credentials
    // enumerated in this array. This allows RPs to limit the creation of multiple credentials for the
    // same account on a single authenticator.
    if (mcp.excludeList) |ecllist| {
        for (ecllist) |ecl| {
            const uid = std.mem.bytesToValue(uuid.Uuid, ecl.id[0..16]);
            const urn = uuid.urn.serialize(uid);

            var cred = auth.callbacks.readCred(.{ .id = urn[0..] }, auth.allocator) catch {
                // TODO: return error for all errors except DoesNotExist

                // If we cant find the credential, it doesn't exist
                continue;
            };
            if (cred.len == 0) continue;
            defer {
                cred[0].deinit(auth.allocator);
                auth.allocator.free(cred);
            }
            const mac_key = deriveMacKey(ms);
            if (!cred[0].verifyMac(&mac_key)) {
                // MAC validation failed
                continue;
            }

            const cred_policy = cred[0].policy;

            if (fido.ctap.extensions.CredentialCreationPolicy.userVerificationRequired != cred_policy) {
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
                    _ = auth.callbacks.up(.MakeCredential, null, null);
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
                        _ = auth.callbacks.up(.MakeCredential, null, null);
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
                if (auth.callbacks.up(.MakeCredential, &mcp.user, &mcp.rp) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up(.MakeCredential, &mcp.user, &mcp.rp) != .Accepted) {
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
    const policy = if (mcp.extensions) |ext| blk: {
        // Set the requested policy
        if (ext.credProtect) |pol| {
            break :blk pol;
        } else {
            break :blk fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
        }
    } else blk: {
        break :blk fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
    };

    var extensions: fido.ctap.extensions.Extensions = .{
        .credProtect = policy,
    };

    // Create a new universally unique identifier as ID
    const id = uuid.v4.new2(auth.callbacks.rand);

    // Create Entry if rk required
    var entry = try fido.ctap.authenticator.Credential.allocInit(
        id,
        &mcp.user,
        mcp.rp.id,
        alg.?.alg,
        policy,
        auth.allocator,
        // The authenticator generates two random 32-byte values (called CredRandomWithUV
        // and CredRandomWithoutUV) and associates them with the credential.
        auth.callbacks.rand,
    );
    defer {
        if (rk) {
            entry.deinit(auth.allocator);
        }
    }

    if (mcp.extensions) |ext| {
        // Prepare hmac-secret
        if (ext.@"hmac-secret") |hsec| {
            switch (hsec) {
                .create => |flag| {
                    // The creation of the two random values will always succeed,
                    // so we'll always return true.
                    if (flag) {
                        extensions.@"hmac-secret" = .{ .create = true };
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

    const enc_key = deriveEncKey(ms);
    try entry.setPrivateKey(
        key_pair.raw_private_key,
        enc_key,
        auth.callbacks.rand,
        auth.allocator,
    );

    const usageCnt = entry.sign_count;
    entry.sign_count += 1;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 17. + 18. Store credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    if (rk) {
        entry.discoverable = true;
        // If a credential for the same rp.id and account ID already exists
        // on the authenticator, overwrite that credential.
        // TODO
        //if (auth.callbacks.getEntries(
        //    &.{
        //        .{ .key = "RpId", .value = mcp.rp.id },
        //        .{ .key = "UserId", .value = mcp.user.id },
        //    },
        //    auth.allocator,
        //)) |entries| {
        //    defer auth.allocator.free(entries);

        //    if (entries.len > 1) {
        //        std.log.warn("Found two discoverable credentials with the same rpId and uId. This shouldn't be!", .{});
        //    }

        //    std.log.info(
        //        "Overwriting credential with id: {s}",
        //        .{std.fmt.fmtSliceHexUpper(entries[0].id)},
        //    );
        //    // Update the old entry
        //    try entries[0].update(&entry.?, auth.callbacks.millis());
        //    // We don't need the new entry anymore
        //    entry.?.deinit();
        //} else {
        //    auth.callbacks.addEntry(entry.?) catch {
        //        return fido.ctap.StatusCodes.ctap2_err_key_store_full;
        //    };
        //}
    }
    std.debug.print("{any}\n", .{entry});
    const mac_key = deriveMacKey(ms);
    entry.updateMac(&mac_key);
    auth.callbacks.updateCred(&entry, auth.allocator) catch |err| {
        std.log.err("authenticatorMakeCredential: unable to create credential ({any})", .{err});
        return err;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 19. Create attestation statement
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const uid = try uuid.urn.deserialize(entry._id[0..]);
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
        .signCount = @as(u32, @intCast(usageCnt)),
        .attestedCredentialData = .{
            .aaguid = auth.settings.aaguid,
            .credential_length = 16,
            .credential_id = std.mem.asBytes(&uid),
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
