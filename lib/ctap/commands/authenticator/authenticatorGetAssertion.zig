const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const uuid = @import("uuid");
const helper = @import("helper.zig");
const deriveMacKey = fido.ctap.crypto.master_secret.deriveMacKey;
const deriveEncKey = fido.ctap.crypto.master_secret.deriveEncKey;

pub fn authenticatorGetAssertion(
    auth: *fido.ctap.authenticator.Authenticator,
    gap: *const fido.ctap.request.GetAssertion,
    out: anytype,
) !fido.ctap.StatusCodes {
    std.debug.print("GET ASSERTION\n", .{});
    // Remove the credential list form the previous getAssertion
    // call if one exists.
    if (auth.credential_list != null) {
        auth.credential_list.?.deinit(auth.allocator);
        auth.credential_list = null;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 1\n", .{});
    var status = helper.verifyPinUvAuthParam(auth, gap);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 2\n", .{});
    var uv_response = false;
    var up_response = false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 3\n", .{});
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
    std.debug.print("GET ASSERTION 4\n", .{});
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
    std.debug.print("GET ASSERTION 5\n", .{});
    if (auth.isProtected()) {
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
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 7. Locate credentials
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 6\n", .{});

    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("authenticatorGetAssertion: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer settings.deinit(auth.allocator);
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("authenticatorGetAssertion: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const ms = settings.getSecret(auth.secret.enc) catch |err| {
        std.log.err("authenticatorGetAssertion: unable to decrypt secret", .{});
        return err;
    };

    var credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(
        auth.allocator,
        try auth.callbacks.readCred(.{ .rpId = gap.rpId }, auth.allocator),
    );

    //if (gap.allowList) |allowList| {
    //    for (allowList) |desc| {
    //        const credId = fido.ctap.crypto.Id.from_raw(desc.id[0..], ms, gap.rpId) catch {
    //            continue;
    //        };
    //        try credentials.append(credId);
    //    }
    //} else {
    //    if (auth.callbacks.getEntries(
    //        &.{.{ .key = "RpId", .value = gap.rpId }},
    //        auth.allocator,
    //    )) |entries| {
    //        defer auth.allocator.free(entries);

    //        for (entries) |entry| {
    //            // Each credential is bound to a rpId by a MAC, i.e., if this succeeds we know
    //            // that this credential is bound to the specified rpId
    //            const credId = fido.ctap.crypto.Id.from_raw(entry.id[0..], ms, gap.rpId) catch {
    //                continue;
    //            };
    //            try credentials.append(credId);
    //        }
    //    }
    //}

    var i: usize = 0;
    while (i < credentials.items.len) : (i += 1) {
        if (gap.allowList) |allowList| {
            // Remove all credentials not listed in allow list
            var found: bool = false;
            for (allowList) |desc| {
                const uid = std.mem.bytesToValue(uuid.Uuid, desc.id[0..16]);
                const urn = uuid.urn.serialize(uid);

                if (std.mem.eql(u8, urn[0..], credentials.items[i]._id)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                const item = credentials.swapRemove(i);
                item.deinit(auth.allocator);
            }
        }

        const policy = credentials.items[i].policy;

        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (fido.ctap.extensions.CredentialCreationPolicy.userVerificationRequired == policy and !uv_response) {
            const item = credentials.swapRemove(i);
            item.deinit(auth.allocator);
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptionalWithCredentialIDList == policy and gap.allowList == null and !uv_response) {
            const item = credentials.swapRemove(i);
            item.deinit(auth.allocator);
        }
    }

    if (credentials.items.len == 0) {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 9. Check user presence
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 7\n", .{});
    if (up) {
        if (gap.pinUvAuthParam != null) {
            var token = switch (gap.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };
            if (!token.getUserPresentFlagValue()) {
                if (auth.callbacks.up(
                    .GetAssertion,
                    null,
                    &fido.common.RelyingParty{ .id = gap.rpId },
                ) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up(
                    .GetAssertion,
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
    std.debug.print("GET ASSERTION 8\n", .{});

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
    std.debug.print("GET ASSERTION 9\n", .{});
    var cred = if (gap.allowList == null and credentials.items.len > 1 and auth.callbacks.select_discoverable_credential != null and
        (up or uv))
    blk: {
        var users = std.ArrayList(fido.common.User).init(auth.allocator);
        defer users.deinit();

        // TODO: allow selection of credential

        break :blk credentials.pop();
    } else blk: {
        break :blk credentials.pop();
    };

    // Seems like this is a discoverable credential, because we
    // just discovered it :)
    var usageCnt = cred.sign_count;
    cred.sign_count += 1;

    var user = if (uv_response) blk: {
        // User identifiable information (name, DisplayName, icon)
        // inside the publicKeyCredentialUserEntity MUST NOT be returned
        // if user verification is not done by the authenticator
        break :blk fido.common.User{
            .id = cred.user_id,
            .name = cred.user_name,
            .displayName = cred.user_display_name,
        };
    } else blk: {
        break :blk null;
    };

    if (credentials.items.len >= 1) {
        // Copy the remaining credential Ids for later use by authenticatorGetNextAssertion
        auth.credential_list = .{
            .list = try auth.allocator.dupe(fido.ctap.authenticator.Credential, credentials.items),
            .time_stamp = auth.callbacks.millis(),
        };
    } else {
        for (credentials.items) |item| {
            item.deinit(auth.allocator);
        }
        credentials.deinit();
    }

    // select algorithm based on credential
    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (auth.algorithms) |_alg| blk: {
        if (cred.alg == _alg.alg) {
            alg = _alg;
            break :blk;
        }
    }

    if (alg == null) {
        std.log.err("Unknown algorithm for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred._id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const enc_key = deriveEncKey(ms);
    const raw_key = try cred.getPrivateKey(enc_key, auth.allocator);
    defer auth.allocator.free(raw_key);

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 13. Sign data
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    std.debug.print("GET ASSERTION 10\n", .{});
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
        .signCount = @intCast(usageCnt),
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
    const sig = if (alg.?.sign(
        raw_key,
        &.{ authData.items, &gap.clientDataHash },
        auth.allocator,
    )) |signature| signature else {
        std.log.err("signature creation failed for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred._id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(sig);

    const uid = try uuid.urn.deserialize(cred._id[0..]);
    const gar = fido.ctap.response.GetAssertion{
        .credential = .{
            .type = .@"public-key",
            .id = std.mem.asBytes(&uid),
        },
        .authData = authData.items,
        .signature = sig,
        .user = user,
    };

    const mac_key = deriveMacKey(ms);
    cred.updateMac(&mac_key);
    auth.callbacks.updateCred(&cred, auth.allocator) catch |err| {
        std.log.err("authenticatorGetAssertion: unable to update credential ({any})", .{err});
        return err;
    };

    try cbor.stringify(gar, .{ .allocator = auth.allocator }, out);

    if (auth.credential_list) |*cl| {
        // We remember authData and clientDataHash for authenticatorGetNextAssertion
        cl.authData = auth_data;
        cl.clientDataHash = gap.clientDataHash;
    }

    return status;
}
