const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

pub fn authenticatorGetAssertion(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    const di = cbor.DataItem.new(request) catch {
        return .ctap2_err_invalid_cbor;
    };
    const gap = cbor.parse(fido.ctap.request.GetAssertion, di, .{
        .allocator = auth.allocator,
    }) catch {
        std.log.err("unable to map request to `GetAssertion` data type", .{});
        return .ctap2_err_invalid_cbor;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const status = helper.verifyPinUvAuthParam(auth, gap);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_response = false;
    var up_response = false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const uv_supported = auth.uvSupported();

    var uv = gap.requestsUv();
    uv = if (gap.pinUvAuthParam != null) false else uv; // pin overwrites uv
    if (uv and !uv_supported) {
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const rk = gap.requestsRk();
    if (rk) {
        return fido.ctap.StatusCodes.ctap2_err_unsupported_option;
    }

    const up = gap.requestsUp();

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate alwaysUv
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const alwaysUv = auth.alwaysUv() catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    const noMcGaPermissionsWithClientPin = auth.noMcGaPermissionsWithClientPin();

    if (alwaysUv and up) blk: {
        const is_protected = auth.isProtected();

        if (!is_protected) {
            std.log.err("getAssertion: alwaysUv = true but not protected", .{});
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

        if (gap.pinUvAuthParam != null) {
            // Go to step 6
            break :blk;
        }

        if (uv) {
            // Go to step 6
            break :blk;
        }

        if (!uv and uv_supported) {
            uv = true;
            break :blk;
        }

        if (auth.clientPinSupported() != null and !noMcGaPermissionsWithClientPin) {
            return fido.ctap.StatusCodes.ctap2_err_pin_required;
        }

        // Else: clientPin is not supported
        return fido.ctap.StatusCodes.ctap2_err_operation_denied;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Validate enterpriseAttestation
    //
    // WE ARE CURRENTLY NOT ENTERPRISE ATTESTATION CAPABLE!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (gap.enterpriseAttestation) |ea| {
        std.log.err("getAssertion: enterprise attestation not supported", .{});
        _ = ea;
        return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Verify user
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (auth.isProtected()) {
        if (gap.pinUvAuthParam) |puap| {
            if (!auth.token.verify_token(&gap.clientDataHash, puap.get())) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.permissions & 0x02 == 0) {
                // Check if ga permission is set
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.rp_id) |rp_id| {
                // Match rpIds if possible
                if (!std.mem.eql(u8, gap.rpId.get(), rp_id.get())) {
                    // Ids don't match
                    return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
                }
            }

            if (!auth.token.getUserVerifiedFlagValue()) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            } else {
                uv_response = true;
            }

            // associate the rpId with the token
            if (auth.token.rp_id == null) {
                auth.token.setRpId(gap.rpId.get()) catch {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }
        } else if (uv) {
            const r = std.fmt.allocPrintZ(auth.allocator, "{s}", .{gap.rpId.get()}) catch {
                std.log.err("getAssertion: unable to allocate memory for rpId", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
            defer auth.allocator.free(r);

            const uvState = auth.token.performBuiltInUv(
                true,
                auth,
                "Get Assertion",
                null,
                r,
            );
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
                .AcceptedWithUp => {
                    uv_response = true;
                    up_response = true;
                },
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 8. Locate credentials
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(
        auth.allocator,
        auth.loadCredentials(gap.rpId.get()) catch {
            std.log.err("getAssertion: unable to fetch credentials", .{});
            return fido.ctap.StatusCodes.ctap2_err_no_credentials;
        },
    );
    defer {
        for (credentials.items) |item| {
            item.deinit(auth.allocator);
        }
        credentials.deinit();
    }

    var i: usize = 0;
    while (true) {
        const l = credentials.items.len;
        if (i >= l) break;

        if (gap.allowList) |allowList| {
            var found = false;
            for (allowList.get()) |desc| {
                if (std.mem.eql(u8, desc.id.get(), credentials.items[i].id)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                const item = credentials.swapRemove(i);
                item.deinit(auth.allocator);
                // We don't increment i because we swap the last
                // with the current element
                continue;
            }
        }

        const policy_ = fido.ctap.extensions.CredentialCreationPolicy.fromString(credentials.items[i].getExtensions("credProtect"));
        const policy = if (policy_) |policy| policy else fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;

        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (fido.ctap.extensions.CredentialCreationPolicy.userVerificationRequired == policy and !uv_response) {
            const item = credentials.swapRemove(i);
            item.deinit(auth.allocator);
            // We don't increment i because we swap the last
            // with the current element
            continue;
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptionalWithCredentialIDList == policy and gap.allowList == null and !uv_response) {
            const item = credentials.swapRemove(i);
            item.deinit(auth.allocator);
            // We don't increment i because we swap the last
            // with the current element
            continue;
        }

        i += 1;
    }

    if (credentials.items.len == 0) {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 10. Check user presence
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const r = std.fmt.allocPrintZ(auth.allocator, "{s}", .{gap.rpId.get()}) catch {
        std.log.err("getAssertion: unable to allocate memory for rpId", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(r);

    if (up and !up_response) {
        if (gap.pinUvAuthParam != null) {
            if (!auth.token.getUserPresentFlagValue()) {
                if (auth.callbacks.up("Get Assertion", null, r) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up("Get Assertion", null, r) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        }

        up_response = true;

        auth.token.clearUserPresentFlag();
        auth.token.clearUserVerifiedFlag();
        auth.token.clearPinUvAuthTokenPermissionsExceptLbw();
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. Process extensions
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. + 12. Finally select credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // Sort credentials "newest" to "oldest"
    std.mem.sort(
        fido.ctap.authenticator.Credential,
        credentials.items,
        {},
        comptime fido.ctap.authenticator.Credential.desc,
    );

    var cred = if (credentials.items.len == 1) blk: {
        break :blk credentials.orderedRemove(0);
    } else if (auth.callbacks.select == null or (!uv and !up)) blk: {
        // TODO
        break :blk credentials.orderedRemove(0);
    } else if (auth.callbacks.select != null and (uv or up)) blk: {
        // Let the user select one of the many credentials via
        // device specific interface
        var users = auth.allocator.alloc([*c]const u8, credentials.items.len + 1) catch {
            std.log.err("getAssertion: unable to allocate memory for credentials", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
        defer {
            var oi: usize = 0;
            while (oi < credentials.items.len) : (oi += 1) {
                var ii: usize = 0;
                while (users[oi][ii] != 0) : (ii += 1) {}
                auth.allocator.free(users[oi][0..ii]);
            }
            auth.allocator.free(users);
        }

        for (credentials.items, 0..) |cred, index| {
            users[index] = std.fmt.allocPrintZ(auth.allocator, "{s} ({s})", .{
                if (cred.user.displayName) |name| name.get() else "",
                if (cred.user.name) |name| name.get() else "",
            }) catch {
                std.log.err("getAssertion: allocPrintZ for user data", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
        }
        users[credentials.items.len] = null;

        const rpId = auth.allocator.dupeZ(u8, gap.rpId.get()) catch {
            std.log.err("getAssertion: allocPrintZ for rpId", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
        defer auth.allocator.free(rpId);

        var cred_index = auth.callbacks.select.?(rpId.ptr, users.ptr);
        if (cred_index < 0) {
            std.log.info("no credential selected by user. using default index 0...", .{});
            cred_index = 0;
        }

        break :blk credentials.orderedRemove(@as(usize, @intCast(cred_index)));
    } else blk: {
        break :blk credentials.orderedRemove(0);
    };
    defer cred.deinit(auth.allocator);

    var write_back: bool = false;
    if (!auth.constSignCount) {
        cred.sign_count += 1;
        write_back = true;
    }

    const usageCnt = cred.sign_count;

    const user: ?fido.common.User = if (uv_response) blk: {
        // User identifiable information (name, DisplayName, icon)
        // inside the publicKeyCredentialUserEntity MUST NOT be returned
        // if user verification is not done by the authenticator
        if (credentials.items.len > 0) {
            break :blk cred.user;
        } else {
            break :blk fido.common.User{ .id = cred.user.id };
        }
    } else blk: {
        break :blk fido.common.User{ .id = cred.user.id };
    };

    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (auth.algorithms) |_alg| {
        if (cred.alg == _alg.alg) {
            alg = _alg;
            break;
        }
    }

    if (alg == null) {
        std.log.err("getAssertion: Unsupported algorithm for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred.id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

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
        .signCount = @intCast(usageCnt),
    };
    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        gap.rpId.get(),
        &auth_data.rpIdHash,
        .{},
    );
    var authData = std.ArrayList(u8).init(auth.allocator);
    defer authData.deinit();
    auth_data.encode(authData.writer()) catch {
        std.log.err("getAssertion: authData encode error", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

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
    var sig_buffer: [256]u8 = undefined;
    const sig = if (alg.?.sign(
        cred.private_key,
        &.{ authData.items, &gap.clientDataHash },
        &sig_buffer,
    )) |signature| signature else {
        std.log.err("getAssertion: signature creation failed for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred.id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    const gar = fido.ctap.response.GetAssertion{
        .credential = fido.common.PublicKeyCredentialDescriptor.new(cred.id, .@"public-key", null) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        },
        .authData = authData.items,
        .signature = sig,
        .user = user,
    };

    if (write_back) {
        // If the sign count is not updated we don't need to update the
        // credentials DB entry, i.e. shared resident keys (passkeys)
        // are not at risk getting out of sync.
        auth.writeCredential(cred.id, cred.rp.id.get(), &cred) catch {
            std.log.err("getAssertion: unable to update credential", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    cbor.stringify(gar, .{ .allocator = auth.allocator }, out.writer()) catch {
        std.log.err("getAssertion: cbor encoding error", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    return status;
}
