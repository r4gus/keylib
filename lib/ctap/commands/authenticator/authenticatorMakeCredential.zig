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
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    const di = cbor.DataItem.new(request) catch {
        return .ctap2_err_invalid_cbor;
    };
    const mcp = cbor.parse(fido.ctap.request.MakeCredential, di, .{
        .allocator = auth.allocator,
    }) catch {
        std.log.err("unable to map request to `MakeCredential` data type", .{});
        return .ctap2_err_invalid_cbor;
    };
    defer mcp.deinit(auth.allocator);

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
    const uv_supported = auth.uvSupported();
    const rk_supported = auth.rkSupported();

    var uv = mcp.requestsUv();
    uv = if (mcp.pinUvAuthParam != null) false else uv; // pin overwrites uv
    if (uv and !uv_supported) {
        // If the authenticator does not support a built-in user verification
        // method end the operation by returning CTAP2_ERR_INVALID_OPTION
        std.log.err("makeCredential: uv requested by client but not supported", .{});
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
    const alwaysUv = auth.alwaysUv() catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
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
        // This step returns an error if the platform tries to create a discoverable
        // credential without performing some form of user verification.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null and rk) {
            std.log.err("makeCredential: uv required for resident key", .{});
            if (auth.clientPinSupported()) |supported| {
                if (supported and !noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            }
            return fido.ctap.StatusCodes.ctap2_err_operation_denied;
        }
    } else {
        // This step returns an error if the platform tries to create a credential
        // without performing some form of user verification when the makeCredUvNotRqd
        // option ID in authenticatorGetInfo's response is present with the value
        // false or is absent.
        if (auth.isProtected() and !uv and mcp.pinUvAuthParam == null) {
            std.log.err("makeCredential: requires user verification but uv = false and pinUvAuthParam not present", .{});
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
        if (mcp.pinUvAuthParam) |puap| {
            if (!auth.token.verify_token(&mcp.clientDataHash, puap, auth.allocator)) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.permissions & 0x02 == 0) {
                // Check if ga permission is set
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.rp_id) |rp_id| {
                // Match rpIds if possible
                if (!std.mem.eql(u8, mcp.rp.id.get(), rp_id)) {
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
                auth.token.setRpId(mcp.rp.id.get());
            }
        } else if (uv) {
            const u = std.fmt.allocPrintZ(auth.allocator, "{s} ({s})", .{
                if (mcp.user.displayName) |dn| dn.get() else "???",
                if (mcp.user.name) |dn| dn.get() else "???",
            }) catch {
                std.log.err("MakeCredential: allocPrintZ for user", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
            defer auth.allocator.free(u);

            const r = std.fmt.allocPrintZ(auth.allocator, "{s}", .{mcp.rp.id.get()}) catch {
                std.log.err("MakeCredential: allocPrintZ for rpId", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
            defer auth.allocator.free(r);

            const uvState = auth.token.performBuiltInUv(
                true,
                auth,
                "Make Credential",
                u,
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

    const settings = auth.loadSettings() catch |e| {
        std.log.err("authenticatorMakeCredential: Unable to fetch Settings ({any})", .{e});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    _ = settings;

    const u = std.fmt.allocPrintZ(auth.allocator, "{s} ({s})", .{
        if (mcp.user.displayName) |dn| dn.get() else "???",
        if (mcp.user.name) |dn| dn.get() else "???",
    }) catch {
        std.log.err("makeCredential: allocPrintZ for user", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(u);

    const r = std.fmt.allocPrintZ(auth.allocator, "{s}", .{mcp.rp.id.get()}) catch {
        std.log.err("makeCredential: allocPrintZ for user", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(r);

    if (mcp.excludeList) |ecllist| {
        for (ecllist) |item| {
            var cred = auth.loadCredential(item.id.get()) catch {
                continue;
            };
            defer cred.deinit(auth.allocator);
            // If the credential was created by this authenticator: Return.

            const policy_ = fido.ctap.extensions.CredentialCreationPolicy.fromString(cred.getExtensions("credProtect"));
            const policy = if (policy_) |policy| policy else fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
            if (.userVerificationRequired != policy) {
                var userPresentFlagValue = false;
                if (mcp.pinUvAuthParam) |_| {
                    userPresentFlagValue = auth.token.getUserPresentFlagValue();
                } else { // e.g. set because of built in uv
                    userPresentFlagValue = up_response;
                }

                if (!userPresentFlagValue) {
                    _ = auth.callbacks.up("Make Credential", u, r);
                    return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_credential_excluded;
                }
            } else {
                if (uv_response) {
                    var userPresentFlagValue = false;
                    if (mcp.pinUvAuthParam) |_| {
                        userPresentFlagValue = auth.token.getUserPresentFlagValue();
                    } else { // e.g. set because of built in uv
                        userPresentFlagValue = up_response;
                    }

                    if (!userPresentFlagValue) {
                        _ = auth.callbacks.up("Make Credential", u, r);
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

    // ++++++++++++++++++++++++++++++++++++++++
    // 13. SEE Step 11
    // ++++++++++++++++++++++++++++++++++++++++

    // ++++++++++++++++++++++++++++++++++++++++
    // 14
    // ++++++++++++++++++++++++++++++++++++++++

    if (up) {
        if (mcp.pinUvAuthParam != null) {
            if (!auth.token.getUserPresentFlagValue()) {
                if (auth.callbacks.up("Make Credential", u, r) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up("Make Credential", u, r) != .Accepted) {
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
    // 15. Process extensions
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var extensions = fido.ctap.extensions.Extensions{};

    // Policy
    var policy = fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;

    if (mcp.extensions) |ext| {
        if (ext.credProtect) |pol| {
            policy = pol;
        }
    }
    // We will always set a policy
    extensions.credProtect = policy;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 16. Create a new credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const id = auth.allocator.alloc(u8, 32) catch {
        std.log.err("makeCredential: unable to allocate memory for credId", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    auth.random.bytes(id);
    for (id) |*b| {
        // disallow 0 bytes
        // -> The callbacks work with C strings and we don't pass a length, i.e.
        //    0 terminates a string. If we would allow 0 bytes then the id would
        //    get cut off.
        while (b.* == 0) {
            b.* = auth.random.int(u8);
        }
    }

    const key_pair = if (alg.create(
        auth.random,
        auth.allocator,
    )) |kp| kp else {
        std.log.err("MakeCredential: unable to generate credential for alg = {any}", .{alg.alg});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer {
        auth.allocator.free(key_pair.cose_public_key);
        auth.allocator.free(key_pair.raw_private_key);
    }

    var entry = fido.ctap.authenticator.Credential{
        .id = id,
        .user = mcp.user,
        .rp = mcp.rp,
        .sign_count = 0, // the first signature will be included in the response
        .alg = alg.alg,
        .private_key = key_pair.raw_private_key,
        .created = auth.milliTimestamp(),
    };
    defer auth.allocator.free(entry.id);
    entry.setExtension("credProtect", fido.ctap.extensions.CredentialCreationPolicy.toString(policy), auth.allocator) catch {
        std.log.err("MakeCredential: unable to set policy {any}", .{policy});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 17. + 18. Store credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (rk) {
        std.log.info("MakeCredential: creating resident key", .{});
        const credentials: ?[]fido.ctap.authenticator.Credential = auth.loadCredentials(mcp.rp.id.get()) catch |err| blk: {
            if (err == error.NoData) {
                std.log.info(
                    "makeCredential: no credentials associated with rpId {s} found",
                    .{std.fmt.fmtSliceHexLower(mcp.rp.id.get())},
                );
                break :blk null;
            } else {
                std.log.err(
                    "makeCredential: unable to fetch credentials associated with rpId {s}",
                    .{mcp.rp.id.get()},
                );
                return fido.ctap.StatusCodes.ctap1_err_other;
            }
        };
        defer {
            if (credentials) |creds| {
                for (creds) |cred| {
                    cred.deinit(auth.allocator);
                }
                auth.allocator.free(creds);
            }
        }

        if (credentials) |creds| {
            for (creds) |cred| {
                if (std.mem.eql(u8, cred.user.id.get(), entry.user.id.get())) {
                    // If a credential for the same rp.id and account ID already exists
                    // on the authenticator, overwrite that credential.
                    std.log.warn("makeCredential: rk with the same user and rp id already exist", .{});
                    std.log.info("makeCredential: overwriting existing credentials with id {s}", .{
                        cred.id,
                    });
                    auth.allocator.free(entry.id);
                    entry.id = auth.allocator.dupe(u8, cred.id) catch {
                        std.log.err("makeCredential: unable to dupe credId", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    };
                }
            }
        }

        entry.discoverable = true;
    }

    auth.writeCredential(entry.id, mcp.rp.id.get(), &entry) catch |err| {
        std.log.err("makeCredential: unable to create credential ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

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
            .at = 1, // self attestation
            .ed = 0,
        },
        .signCount = 0,
        .attestedCredentialData = .{
            .aaguid = auth.settings.aaguid,
            .credential_length = @intCast(entry.id.len),
            .credential_id = entry.id,
            .credential_public_key = key_pair.cose_public_key,
        },
        .extensions = extensions,
    };
    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        mcp.rp.id.get(),
        &auth_data.rpIdHash,
        .{},
    );

    const stmt = switch (auth.attestation) {
        .Self => blk: {
            var authData = std.ArrayList(u8).init(auth.allocator);
            defer authData.deinit();
            auth_data.encode(authData.writer()) catch {
                std.log.err("makeCredential: auth data encoding error", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };

            const sig = alg.sign(
                key_pair.raw_private_key,
                &.{
                    authData.items,
                    &mcp.clientDataHash,
                },
                auth.allocator,
            ).?;
            defer auth.allocator.free(sig);

            break :blk fido.common.AttestationStatement{ .@"packed" = .{
                .alg = alg.alg,
                .sig = (fido.common.dt.ABS256B.fromSlice(sig) catch {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                }).?,
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

    cbor.stringify(ao, .{ .allocator = auth.allocator }, out.writer()) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    status = fido.ctap.StatusCodes.ctap1_err_success;
    return status;
}
