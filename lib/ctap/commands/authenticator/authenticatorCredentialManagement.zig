const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

fn validate(
    cmReq: *const fido.ctap.request.CredentialManagement,
    auth: *fido.ctap.authenticator.Authenticator,
) ?fido.ctap.StatusCodes {
    if (cmReq.pinUvAuthParam == null) {
        std.log.err("authenticatorCredentialManagement: pinUvAuthParam missing", .{});
        return fido.ctap.StatusCodes.ctap2_err_pin_required;
    }

    if (!auth.pinUvAuthProtocolSupported(cmReq.pinUvAuthProtocol)) {
        std.log.err("authenticatorCredentialManagement: unsupported pinUvAuthProtocol version ({any})", .{cmReq.pinUvAuthProtocol});
        return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
    }

    var prot = switch (cmReq.pinUvAuthProtocol.?) {
        .V1 => &auth.token.one.?,
        .V2 => &auth.token.two.?,
    };

    // SUB_COMMAND || CBOR(SUB_COMMAND_PARAMS is validated)
    var arr = std.ArrayList(u8).init(auth.allocator);
    defer arr.deinit();
    arr.writer().writeByte(@intFromEnum(cmReq.subCommand)) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    if (cmReq.subCommandParams) |params| {
        cbor.stringify(params, .{}, arr.writer()) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    if (!prot.verify_token(arr.items, cmReq.pinUvAuthParam.?, auth.allocator)) {
        std.log.err("authenticatorCredentialManagement: token verification failed", .{});
        return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    var matches: bool = false;
    if (cmReq.subCommandParams) |scp| {
        if (scp.rpIDHash) |h| {
            var h2: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(prot.rp_id.?, &h2, .{});

            if (std.mem.eql(u8, h[0..], h2[0..])) matches = true;
        }
    }

    if ((prot.permissions & 0x04) != 0x04 or (prot.rp_id != null and !matches)) {
        // cm permission must be set and NO associated permissions RP ID.
        std.log.err("authenticatorCredentialManagement: wrong permission or associated rpId", .{});
        return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    return null;
}

pub fn getKeyInfo(
    id: []const u8,
    cmResp: *fido.ctap.response.CredentialManagement,
    auth: *fido.ctap.authenticator.Authenticator,
) ?fido.ctap.StatusCodes {
    var entry = auth.callbacks.getEntry(id).?;

    // Get the user id
    if (entry.getField("UserId", auth.callbacks.millis())) |user| {
        var a = auth.allocator.alloc(u8, user.len) catch {
            std.log.err("Out of memory", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
        @memcpy(a, user);
        cmResp.user = .{ .id = a };
    } else {
        std.log.err("authenticatorCredentialManagement (enumerateRPsBegin): unable to fetch UserId", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // Get the credential id
    cmResp.credentialID = .{
        .id = id,
        .type = .@"public-key",
    };

    // Get the public key
    if (entry.getField("PrivateKey", auth.callbacks.millis())) |pk| {
        if (entry.getField("Algorithm", auth.callbacks.millis())) |algo| {
            const algorithm = std.mem.bytesToValue(cbor.cose.Algorithm, algo[0..4]);

            var alg: ?fido.ctap.crypto.SigAlg = null;
            for (auth.algorithms) |_alg| blk: {
                if (algorithm == _alg.alg) {
                    alg = _alg;
                    break :blk;
                }
            }

            if (alg == null) {
                std.log.err("Unsupported algorithm", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            }

            if (alg.?.from_priv(pk)) |public_key| {
                cmResp.publicKey = public_key;
            } else {
                std.log.err("Unable to derive public key", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            }
        } else {
            std.log.err("Unable to fetch Algorithm", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        }
    } else {
        std.log.err("Unable to fetch PrivateKey", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // Get policy
    if (entry.getField("Policy", auth.callbacks.millis())) |pol| {
        if (fido.ctap.extensions.CredentialCreationPolicy.fromString(pol)) |p| {
            cmResp.credProtect = p;
        } else {
            std.log.err("Unable to translate Policy", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        }
    } else {
        std.log.err("Unable to fetch Policy", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // TODO: Return large blob key (not yet supported)

    return null;
}

pub fn authenticatorCredentialManagement(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
    command: []const u8,
) !fido.ctap.StatusCodes {
    const cmReq = try cbor.parse(
        fido.ctap.request.CredentialManagement,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = auth.allocator,
        },
    );
    defer cmReq.deinit(auth.allocator);

    var cmResp: fido.ctap.response.CredentialManagement = .{};
    defer cmResp.deinit(auth.allocator);

    // State for different sub-commands
    const S = struct {
        pub var rpId: ?struct {
            ids: std.ArrayList([]const u8),
            time_stamp: i64,
            prot: fido.ctap.pinuv.common.PinProtocol,
            token: [32]u8,
        } = null;

        pub fn deinit(a: std.mem.Allocator) void {
            if (rpId) |rpId_state| {
                for (rpId_state.ids.items) |id| {
                    a.free(id);
                }
                rpId_state.ids.deinit();

                rpId = null;
            }
        }
    };

    // Invalidate state after 30 seconds or if the pin token has changed
    if (S.rpId) |rpId_state| {
        var prot = switch (rpId_state.prot) {
            .V1 => &auth.token.one.?,
            .V2 => &auth.token.two.?,
        };
        const diff: i64 = auth.callbacks.millis() - rpId_state.time_stamp;

        if (diff >= 30000 or !std.mem.eql(u8, prot.pin_token[0..], rpId_state.token[0..])) {
            S.deinit(auth.allocator);
        }
    }

    switch (cmReq.subCommand) {
        .getCredsMetadata => {
            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            const el: u32 = if (auth.callbacks.getEntries()) |entries| @intCast(entries.len) else 0;
            cmResp.existingResidentCredentialsCount = el;
            cmResp.maxPossibleRemainingResidentCredentialsCount = if (auth.settings.remainingDiscoverableCredentials) |rdc| @as(u32, @intCast(rdc)) - el else 1;
        },
        .enumerateRPsBegin => {
            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            // check if discoverable credentials exist on this authenticator
            const entries = if (auth.callbacks.getEntries()) |entries| entries else return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            if (entries.len == 0) return fido.ctap.StatusCodes.ctap2_err_no_credentials;

            if (S.rpId == null) {
                var prot = switch (cmReq.pinUvAuthProtocol.?) {
                    .V1 => &auth.token.one.?,
                    .V2 => &auth.token.two.?,
                };

                S.rpId = .{
                    .ids = std.ArrayList([]const u8).init(auth.allocator),
                    .time_stamp = auth.callbacks.millis(),
                    .prot = cmReq.pinUvAuthProtocol.?,
                    .token = prot.pin_token,
                };
            }

            for (entries) |*entry| {
                if (entry.getField("RpId", auth.callbacks.millis())) |rpId| {
                    var a = try auth.allocator.alloc(u8, rpId.len);
                    @memcpy(a, rpId);

                    var found: bool = false;
                    for (S.rpId.?.ids.items) |id| {
                        if (std.mem.eql(u8, id, a)) {
                            found = true;
                        }
                    }

                    if (!found) try S.rpId.?.ids.append(a);
                } else {
                    std.log.warn("authenticatorCredentialManagement (enumerateRPsBegin): credential with id {s} has no associated rpId", .{std.fmt.fmtSliceHexUpper(entry.id)});
                }
            }

            cmResp.totalRPs = @intCast(S.rpId.?.ids.items.len);
            const id = S.rpId.?.ids.pop();
            var idh: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(id, &idh, .{});
            cmResp.rpIDHash = idh;
            cmResp.rp = fido.common.RelyingParty{ .id = id };
        },
        .enumerateRPsGetNextRP => {
            if (S.rpId) |*rpIds| {
                const id = rpIds.ids.pop();
                var idh: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(id, &idh, .{});
                cmResp.rpIDHash = idh;
                cmResp.rp = fido.common.RelyingParty{ .id = id };
            } else {
                // This is actualy not required in the standard but its possible
                // so it should be handled
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            }
        },
        .enumerateCredentialsBegin => {
            if (cmReq.subCommandParams == null or cmReq.subCommandParams.?.rpIDHash == null) {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            const rpIdHash = cmReq.subCommandParams.?.rpIDHash.?;

            const entries = if (auth.callbacks.getEntries()) |entries| entries else return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            if (entries.len == 0) return fido.ctap.StatusCodes.ctap2_err_no_credentials;

            if (S.rpId == null) {
                var prot = switch (cmReq.pinUvAuthProtocol.?) {
                    .V1 => &auth.token.one.?,
                    .V2 => &auth.token.two.?,
                };

                S.rpId = .{
                    .ids = std.ArrayList([]const u8).init(auth.allocator),
                    .time_stamp = auth.callbacks.millis(),
                    .prot = cmReq.pinUvAuthProtocol.?,
                    .token = prot.pin_token,
                };
            }

            var RP_ID: ?[]const u8 = null;
            for (entries) |*entry| {
                if (entry.getField("RpId", auth.callbacks.millis())) |rpId| {
                    var idh: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(rpId, &idh, .{});

                    if (!std.mem.eql(u8, idh[0..], rpIdHash[0..])) continue;
                    RP_ID = rpId;

                    var a = try auth.allocator.alloc(u8, entry.id.len);
                    @memcpy(a, entry.id);
                    try S.rpId.?.ids.append(a);
                } else {
                    std.log.warn("authenticatorCredentialManagement (enumerateRPsBegin): credential with id {s} has no associated rpId", .{std.fmt.fmtSliceHexUpper(entry.id)});
                }
            }

            if (S.rpId.?.ids.items.len == 0) {
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            }

            // Get total credentials
            cmResp.totalCredentials = @intCast(S.rpId.?.ids.items.len);
            const id = S.rpId.?.ids.pop();

            if (getKeyInfo(id, &cmResp, auth)) |err| {
                return err;
            }
        },
        .enumerateCredentialsGetNextCredential => {
            if (S.rpId) |*rpIds| {
                const id = rpIds.ids.pop();

                if (getKeyInfo(id, &cmResp, auth)) |err| {
                    return err;
                }
            } else {
                // This is actualy not required in the standard but its possible
                // so it should be handled
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            }
        },
        .deleteCredential => {
            if (cmReq.subCommandParams == null or cmReq.subCommandParams.?.credentialID == null) {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            auth.callbacks.removeEntry(cmReq.subCommandParams.?.credentialID.?.id) catch |err| {
                if (err == error.DoesNotExist) {
                    return fido.ctap.StatusCodes.ctap2_err_no_credentials;
                } else {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                }
            };

            try auth.callbacks.persist();
        },
        .updateUserInformation => {
            if (cmReq.subCommandParams == null or
                cmReq.subCommandParams.?.credentialID == null or
                cmReq.subCommandParams.?.user == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            var entry = if (auth.callbacks.getEntry(cmReq.subCommandParams.?.credentialID.?.id)) |e| e else {
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            };

            if (!std.mem.eql(
                u8,
                cmReq.subCommandParams.?.credentialID.?.id,
                cmReq.subCommandParams.?.user.?.id,
            )) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Replace, add or remove the user name
            if (cmReq.subCommandParams.?.user.?.name) |name| {
                if (entry.getField("UserName", auth.callbacks.millis())) |_| {
                    entry.updateField("UserName", name, auth.callbacks.millis()) catch {
                        return fido.ctap.StatusCodes.ctap2_err_key_store_full;
                    };
                } else {
                    entry.addField(.{ .key = "UserName", .value = name }, auth.callbacks.millis()) catch {
                        return fido.ctap.StatusCodes.ctap2_err_key_store_full;
                    };
                }
            } else blk: {
                const uname = entry.removeField("UserName", auth.callbacks.millis()) catch {
                    break :blk; // this is a problem but not such a big one
                };
                if (uname) |name| {
                    entry.allocator.free(name.key);
                    entry.allocator.free(name.value);
                }
            }

            // Replace, add or remove the display name
            if (cmReq.subCommandParams.?.user.?.displayName) |displayName| {
                if (entry.getField("UserDisplayName", auth.callbacks.millis())) |_| {
                    entry.updateField("UserDisplayName", displayName, auth.callbacks.millis()) catch {
                        return fido.ctap.StatusCodes.ctap2_err_key_store_full;
                    };
                } else {
                    entry.addField(.{ .key = "UserDisplayName", .value = displayName }, auth.callbacks.millis()) catch {
                        return fido.ctap.StatusCodes.ctap2_err_key_store_full;
                    };
                }
            } else blk: {
                const dname = entry.removeField("UserDisplayName", auth.callbacks.millis()) catch {
                    break :blk; // this is a problem but not such a big one
                };
                if (dname) |name| {
                    entry.allocator.free(name.key);
                    entry.allocator.free(name.value);
                }
            }
        },
    }

    try cbor.stringify(cmResp, .{}, out);
    return fido.ctap.StatusCodes.ctap1_err_success;
}
