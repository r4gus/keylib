const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

pub fn authenticatorGetAssertion(
    auth: *fido.ctap.authenticator.Authenticator,
    gap: *const fido.ctap.request.GetAssertion,
    out: anytype,
) !fido.ctap.StatusCodes {
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var status = helper.verifyPinUvAuthParam(auth, gap);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_response = false;
    var up_response = false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv: bool = false;
    var uv_supported = false;
    var up: bool = true;
    var rk: bool = false;

    if (gap.options) |options| {
        uv = if (options.uv) |_uv| _uv else false;
        uv = if (gap.pinUvAuthParam) |_| false else uv;

        rk = if (options.rk) |_rk| _rk else false;

        up = if (options.up) |_up| _up else true;
    }

    if (auth.settings.options) |options| {
        if (options.uv != null and options.uv.? and auth.callbacks.uv != null) {
            uv_supported = true;
        }
    }

    if (uv and !uv_supported) {
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    if (rk) {
        return fido.ctap.StatusCodes.ctap2_err_unsupported_option;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate alwaysUv
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const alwaysUv = if (auth.settings.options != null and auth.settings.options.?.alwaysUv != null) auth.settings.options.?.alwaysUv.? else false;

    if (alwaysUv and up) {
        var skip = false;

        if (!auth.isProtected()) {
            if (auth.getClientPinOption() and !auth.getNoMcGaPermissionsWithClientPinOption()) {
                return fido.ctap.StatusCodes.ctap2_err_pin_required;
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }

        if (gap.pinUvAuthParam) |_| {
            skip = true;
        }

        if (!skip and auth.getUvOption()) {
            skip = true;
        }

        if (!skip and !uv and auth.buildInUvEnabled()) {
            // If the "uv" option is false and the authenticator supports a built-in
            // user verification method, and the user verification method is enabled
            // then: Let the "uv" option be treated as being present with the value true.
            uv = true;
            skip = true;
        }

        if (!skip and auth.getClientPinOption() and !auth.getNoMcGaPermissionsWithClientPinOption()) {
            return fido.ctap.StatusCodes.ctap2_err_pin_required;
        } else if (!skip) {
            return fido.ctap.StatusCodes.ctap2_err_operation_denied;
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Verify user
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (!auth.isProtected()) {
        if (gap.pinUvAuthParam) |puap| {
            var pinuvprot = switch (gap.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            if (!pinuvprot.verify_token(&gap.clientDataHash, &puap, auth.allocator)) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (pinuvprot.permissions & 0x02 == 0) {
                // Check if ga permission is set
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (pinuvprot.rp_id) |rp_id| {
                // Match rpIds if possible
                if (!std.mem.eql(u8, gap.rpId, rp_id)) {
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
                pinuvprot.setRpId(gap.rpId);
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
    // 7. Locate credentials
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var credentials = std.ArrayList(fido.ctap.authenticator.Credential).init(
        auth.allocator,
    );
    defer {
        for (credentials.items) |cred| {
            cred.deinit(auth.allocator);
        }
        credentials.deinit();
    }

    if (gap.allowList) |allowList| {
        for (allowList) |desc| {
            // Try to load credential...
            const cred_cbor = auth.callbacks.load_credential_by_id(
                desc.id,
                auth.allocator,
            ) catch {
                continue;
            };
            defer auth.allocator.free(cred_cbor);
            var di = cbor.DataItem.new(cred_cbor) catch {
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

            try credentials.append(cred);
        }
    } else if (auth.callbacks.load_resident_keys != null) {
        const resident_keys = try auth.callbacks.load_resident_keys.?(gap.rpId, auth.allocator);
        // TODO: free memory of resident_keys

        for (resident_keys) |resident_key| {
            var di = cbor.DataItem.new(resident_key) catch {
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

            try credentials.append(cred);
        }
    }

    var i: usize = 0;
    while (i < credentials.items.len) : (i += 1) {
        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (credentials.items[i].policy == .userVerificationRequired and !uv_response) {
            const cred = credentials.swapRemove(i);
            cred.deinit(auth.allocator);
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (credentials.items[i].policy == .userVerificationOptionalWithCredentialIDList and gap.allowList == null and !uv_response) {
            const cred = credentials.swapRemove(i);
            cred.deinit(auth.allocator);
        }
    }

    if (credentials.items.len == 0) {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 9. Check user presence
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (up) {
        if (gap.pinUvAuthParam != null) {
            var token = switch (gap.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };
            if (!token.getUserPresentFlagValue()) {
                if (auth.callbacks.up(
                    null,
                    &fido.common.RelyingParty{ .id = gap.rpId },
                ) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up(
                    null,
                    &fido.common.RelyingParty{ .id = gap.rpId },
                ) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        }

        up_response = true;

        if (gap.pinUvAuthProtocol) |prot| {
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
    // 10. Process extensions
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    // We go with the weakest policy, if one wants to use a higher policy then she can
    // always provide the `credProtect` extension.
    var policy = fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
    var extensions: ?fido.ctap.extensions.Extensions = null;

    if (gap.extensions) |ext| {
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
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. + 12. Finally select credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var user: ?fido.common.User = null;
    var cred = if (gap.allowList) |_| blk: {
        break :blk credentials.pop();
    } else blk: {
        var _cred = if (credentials.items.len == 1) blk1: {
            break :blk1 credentials.pop();
        } else blk1: {
            // TODO: we'll just use the most recently created credential for
            // now... but should expand this and adhere to the spec
            var k: usize = 1;
            var j: usize = 0;
            var max: u64 = credentials.items[0].time_stamp;

            while (k < credentials.items.len) : (k += 1) {
                if (credentials.items[k].time_stamp > max) {
                    j = k;
                    max = credentials.items[k].time_stamp;
                }
            }

            break :blk1 credentials.swapRemove(j);
        };

        if (uv_response) {
            // User identifiable information (name, DisplayName, icon)
            // inside the publicKeyCredentialUserEntity MUST NOT be returned
            // if user verification is not done by the authenticator
            user = _cred.user;
        }
        break :blk _cred;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 13. Sign data
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var auth_data = fido.common.AuthenticatorData{
        .rpIdHash = undefined,
        .flags = .{
            .up = if (up_response) 1 else 0,
            .rfu1 = 0,
            .uv = if (uv_response) 1 else 0,
            .rfu2 = 0,
            .at = 0,
            .ed = 0,
        },
        .signCount = cred.signCtr,
        .extensions = extensions,
    };
    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        gap.rpId,
        &auth_data.rpIdHash,
        .{},
    );
    var authData = std.ArrayList(u8).init(auth.allocator);
    defer authData.deinit();
    try auth_data.encode(authData.writer());

    // --------------------        ----------------
    // | authenticatorData |      | clientDataHash |
    // --------------------        ----------------
    //         |                          |
    //         ------------------------- | |
    //                                    |
    //         PRIVATE KEY -----------> SIGN
    //                                    |
    //                                    v
    //                           ASSERTION SIGNATURE
    const sig = try cred.key.sign(&.{ authData.items, &gap.clientDataHash }, auth.allocator);
    defer auth.allocator.free(sig);

    const gar = fido.ctap.response.GetAssertion{
        .credential = .{
            .type = .@"public-key",
            .id = &cred.id,
        },
        .authData = authData.items,
        .signature = sig,
        .user = user,
    };

    cred.signCtr += 1;

    var serialized_cred = std.ArrayList(u8).init(auth.allocator);
    cbor.stringify(
        &cred,
        .{},
        serialized_cred.writer(),
    ) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer serialized_cred.deinit();
    auth.callbacks.store_credential_by_id(
        &cred.id,
        serialized_cred.items,
    );

    try cbor.stringify(gar, .{ .allocator = auth.allocator }, out);

    return status;
}
