const std = @import("std");
const cbor = @import("zbor");
const uuid = @import("uuid");
const fido = @import("../../../main.zig");
const deriveMacKey = fido.ctap.crypto.master_secret.deriveMacKey;
const deriveEncKey = fido.ctap.crypto.master_secret.deriveEncKey;

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

    const prot = switch (cmReq.pinUvAuthProtocol.?) {
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
    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("getKeyInfo: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer settings.deinit(auth.allocator);
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("getKeyInfo: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const ms = settings.getSecret(auth.secret.enc) catch {
        std.log.err("getKeyInfo: unable to decrypt secret", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    const uid = std.mem.bytesToValue(uuid.Uuid, id[0..16]);
    const urn = uuid.urn.serialize(uid);
    const entries = auth.callbacks.readCred(.{ .id = urn[0..] }, auth.allocator) catch |err| {
        std.log.err("getKeyInfo: unable to fetch credential with id {s} ({any})", .{
            std.fmt.fmtSliceHexUpper(id),
            err,
        });
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    };
    defer {
        for (entries) |item| {
            item.deinit(auth.allocator);
        }
        auth.allocator.free(entries);
    }
    var entry = entries[0];

    cmResp.user = .{ .id = auth.allocator.dupe(u8, entry.user_id) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    } };

    // Get the credential id
    cmResp.credentialID = .{
        .id = id,
        .type = .@"public-key",
    };

    // Get public key
    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (auth.algorithms) |_alg| blk: {
        if (entry.alg == _alg.alg) {
            alg = _alg;
            break :blk;
        }
    }

    if (alg == null) {
        // THis is only relevant if we import keys from other authenticators
        // or change the settings.
        std.log.err("getKeyInfo: Unsupported algorithm {any}", .{entry.alg});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const enc_key = deriveEncKey(ms);
    const raw_key = entry.getPrivateKey(enc_key, auth.allocator) catch {
        std.log.err("getKeyInfo: unable to decrypt private key", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(raw_key);

    if (alg.?.from_priv(raw_key)) |public_key| {
        cmResp.publicKey = public_key;
    } else {
        std.log.err("Unable to derive public key", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // Get policy
    cmResp.credProtect = entry.policy;

    // TODO: Return large blob key (not yet supported)

    return null;
}

pub fn authenticatorCredentialManagement(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
    command: []const u8,
) !fido.ctap.StatusCodes {
    const cmReq = cbor.parse(
        fido.ctap.request.CredentialManagement,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = auth.allocator,
        },
    ) catch |err| {
        std.log.err("authenticatorCredentialManagement: Unable to parse arguments ({any})", .{err});
        return err;
    };
    defer cmReq.deinit(auth.allocator);

    var cmResp: fido.ctap.response.CredentialManagement = .{};
    defer cmResp.deinit(auth.allocator);

    // Invalidate state after 30 seconds or if the pin token has changed
    if (auth.cred_mngmnt) |rpId_state| {
        var prot = switch (rpId_state.prot) {
            .V1 => &auth.token.one.?,
            .V2 => &auth.token.two.?,
        };
        const diff: i64 = auth.callbacks.millis() - rpId_state.time_stamp;

        if (diff >= 30000 or !std.mem.eql(u8, prot.pin_token[0..], rpId_state.token[0..])) {
            rpId_state.deinit(auth.allocator);
            auth.cred_mngmnt = null;
        }
    }

    switch (cmReq.subCommand) {
        .getCredsMetadata => blk: {
            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            const entries = auth.callbacks.readCred(.{ .all = true }, auth.allocator) catch |err| {
                std.log.err("getCredsMetadata: unable to fetch credentials ({any})", .{
                    err,
                });
                cmResp.existingResidentCredentialsCount = 0;
                cmResp.maxPossibleRemainingResidentCredentialsCount = 1;
                break :blk;
            };
            defer {
                for (entries) |item| {
                    item.deinit(auth.allocator);
                }
                auth.allocator.free(entries);
            }

            cmResp.existingResidentCredentialsCount = @intCast(entries.len);
            cmResp.maxPossibleRemainingResidentCredentialsCount = 1;
        },
        .enumerateRPsBegin => {
            if (validate(&cmReq, auth)) |r| {
                return r;
            }

            const entries = auth.callbacks.readCred(.{ .all = true }, auth.allocator) catch |err| {
                std.log.err("enumerateRPsBegin: unable to fetch credentials ({any})", .{
                    err,
                });
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            };
            defer {
                for (entries) |item| {
                    item.deinit(auth.allocator);
                }
                auth.allocator.free(entries);
            }

            // check if discoverable credentials exist on this authenticator
            if (entries.len == 0) return fido.ctap.StatusCodes.ctap2_err_no_credentials;

            if (auth.cred_mngmnt == null) {
                const prot = switch (cmReq.pinUvAuthProtocol.?) {
                    .V1 => &auth.token.one.?,
                    .V2 => &auth.token.two.?,
                };

                auth.cred_mngmnt = .{
                    .ids = std.ArrayList([]const u8).init(auth.allocator),
                    .time_stamp = auth.callbacks.millis(),
                    .prot = cmReq.pinUvAuthProtocol.?,
                    .token = prot.pin_token,
                };
            }

            for (entries) |entry| {
                var found: bool = false;
                for (auth.cred_mngmnt.?.ids.items) |id| {
                    if (std.mem.eql(u8, id, entry.rp_id)) {
                        found = true;
                    }
                }

                if (!found) try auth.cred_mngmnt.?.ids.append(try auth.allocator.dupe(u8, entry.rp_id));
            }

            cmResp.totalRPs = @intCast(auth.cred_mngmnt.?.ids.items.len);
            const id = auth.cred_mngmnt.?.ids.pop();
            var idh: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(id, &idh, .{});
            cmResp.rpIDHash = idh;
            cmResp.rp = fido.common.RelyingParty{ .id = id };
        },
        .enumerateRPsGetNextRP => {
            if (auth.cred_mngmnt) |*rpIds| {
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

            const entries = auth.callbacks.readCred(.{ .all = true }, auth.allocator) catch |err| {
                std.log.err("enumerateRPsBegin: unable to fetch credentials ({any})", .{
                    err,
                });
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            };
            defer {
                for (entries) |item| {
                    item.deinit(auth.allocator);
                }
                auth.allocator.free(entries);
            }

            if (entries.len == 0) return fido.ctap.StatusCodes.ctap2_err_no_credentials;

            if (auth.cred_mngmnt == null) {
                const prot = switch (cmReq.pinUvAuthProtocol.?) {
                    .V1 => &auth.token.one.?,
                    .V2 => &auth.token.two.?,
                };

                auth.cred_mngmnt = .{
                    .ids = std.ArrayList([]const u8).init(auth.allocator),
                    .time_stamp = auth.callbacks.millis(),
                    .prot = cmReq.pinUvAuthProtocol.?,
                    .token = prot.pin_token,
                };
            }

            for (entries) |entry| {
                var idh: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(entry.rp_id, &idh, .{});

                if (!std.mem.eql(u8, idh[0..], rpIdHash[0..])) continue;

                const uid = try uuid.urn.deserialize(entry._id[0..]);
                try auth.cred_mngmnt.?.ids.append(try auth.allocator.dupe(u8, std.mem.asBytes(&uid)));
            }

            if (auth.cred_mngmnt.?.ids.items.len == 0) {
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            }

            // Get total credentials
            cmResp.totalCredentials = @intCast(auth.cred_mngmnt.?.ids.items.len);
            const id = auth.cred_mngmnt.?.ids.pop();

            if (getKeyInfo(id, &cmResp, auth)) |err| {
                return err;
            }
        },
        .enumerateCredentialsGetNextCredential => {
            if (auth.cred_mngmnt) |*rpIds| {
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

            const uid = std.mem.bytesToValue(
                uuid.Uuid,
                cmReq.subCommandParams.?.credentialID.?.id[0..16],
            );
            const urn = uuid.urn.serialize(uid);
            const entries = auth.callbacks.readCred(.{ .id = urn[0..] }, auth.allocator) catch |err| {
                std.log.err("getCredsMetadata: unable to fetch credentials with id {s} ({any})", .{
                    std.fmt.fmtSliceHexUpper(cmReq.subCommandParams.?.credentialID.?.id),
                    err,
                });
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            };
            defer {
                for (entries) |item| {
                    item.deinit(auth.allocator);
                }
                auth.allocator.free(entries);
            }
            var entry = entries[0];

            auth.callbacks.deleteCred(&entry) catch |err| {
                if (err == error.DoesNotExist) {
                    return fido.ctap.StatusCodes.ctap2_err_no_credentials;
                } else {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                }
            };
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

            const uid = std.mem.bytesToValue(
                uuid.Uuid,
                cmReq.subCommandParams.?.credentialID.?.id[0..16],
            );
            const urn = uuid.urn.serialize(uid);
            const entries = auth.callbacks.readCred(.{ .id = urn[0..] }, auth.allocator) catch |err| {
                std.log.err("getCredsMetadata: unable to fetch credentials with id {s} ({any})", .{
                    std.fmt.fmtSliceHexUpper(cmReq.subCommandParams.?.credentialID.?.id),
                    err,
                });
                return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            };
            defer {
                for (entries) |item| {
                    item.deinit(auth.allocator);
                }
                auth.allocator.free(entries);
            }
            var entry = entries[0];

            // TODO: ???
            //if (!std.mem.eql(
            //    u8,
            //    cmReq.subCommandParams.?.credentialID.?.id,
            //    cmReq.subCommandParams.?.user.?.id,
            //)) {
            //    return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            //}

            if (cmReq.subCommandParams.?.user.?.name) |name| {
                if (entry.user_name) |_name| {
                    auth.allocator.free(_name);
                }
                entry.user_name = try auth.allocator.dupe(u8, name);
            } else {
                if (entry.user_name) |_name| {
                    auth.allocator.free(_name);
                }
                entry.user_name = null;
            }

            if (cmReq.subCommandParams.?.user.?.displayName) |name| {
                if (entry.user_display_name) |_name| {
                    auth.allocator.free(_name);
                }
                entry.user_display_name = try auth.allocator.dupe(u8, name);
            } else {
                if (entry.user_display_name) |_name| {
                    auth.allocator.free(_name);
                }
                entry.user_display_name = null;
            }

            var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
                std.log.err("getKeyInfo: Unable to fetch Settings ({any})", .{err});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
            defer settings.deinit(auth.allocator);
            if (!settings.verifyMac(&auth.secret.mac)) {
                std.log.err("getKeyInfo: Settings MAC validation unsuccessful", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            }

            const ms = settings.getSecret(auth.secret.enc) catch {
                std.log.err("getKeyInfo: unable to decrypt secret", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };

            const mac_key = deriveMacKey(ms);
            entry.updateMac(&mac_key);
            auth.callbacks.updateCred(&entry, auth.allocator) catch |err| {
                std.log.err("authenticatorMakeCredential: unable to create credential ({any})", .{err});
                return err;
            };
        },
    }

    try cbor.stringify(cmResp, .{}, out);
    return fido.ctap.StatusCodes.ctap1_err_success;
}
