const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const Authenticator = @import("../Authenticator.zig");
const data = @import("../data.zig");
const crypto = @import("../crypto.zig");

const cbor = @import("zbor");

pub fn authenticator_client_pin(
    auth: *Authenticator,
    public_data: *data.PublicData,
    out: anytype,
    command: []const u8,
    allocator: std.mem.Allocator,
) !data.StatusCodes {
    const client_pin_param = try cbor.parse(
        data.client_pin.ClientPinParam,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = allocator,
            .field_settings = &.{
                .{ .name = "pinUvAuthProtocol", .alias = "1", .options = .{} },
                .{ .name = "subCommand", .alias = "2", .options = .{} },
                .{ .name = "keyAgreement", .alias = "3", .options = .{} },
                .{ .name = "pinUvAuthParam", .alias = "4", .options = .{} },
                .{ .name = "newPinEnc", .alias = "5", .options = .{} },
                .{ .name = "pinHashEnc", .alias = "6", .options = .{} },
                .{ .name = "permissions", .alias = "9", .options = .{} },
                .{ .name = "rpId", .alias = "10", .options = .{} },
            },
        },
    );
    defer client_pin_param.deinit(allocator);

    var client_pin_response: ?data.client_pin.ClientPinResponse = null;

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            client_pin_response = .{
                .pinRetries = public_data.meta.pin_retries,
                .powerCycleState = false,
            };
        },
        .getKeyAgreement => {
            const protocol = if (client_pin_param.pinUvAuthProtocol) |prot| prot else {
                return data.StatusCodes.ctap2_err_missing_parameter;
            };

            // return error if authenticator doesn't support the selected protocol.
            var protocol_supported: bool = false;
            if (auth.settings.pin_uv_auth_protocols) |pin_uv_auth_protocols| {
                for (pin_uv_auth_protocols) |prot| {
                    if (prot == protocol) {
                        protocol_supported = true;
                        break;
                    }
                }
            }

            if (!protocol_supported) {
                return data.StatusCodes.ctap1_err_invalid_parameter;
            }

            client_pin_response = .{
                .keyAgreement = auth.state.getPublicKey(),
            };
        },
        .changePIN => {
            // Return error if the authenticator does not receive the
            // mandatory parameters for this command.
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.newPinEnc == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.pinUvAuthParam == null)
            {
                return data.StatusCodes.ctap2_err_missing_parameter;
            }

            // If pinUvAuthProtocol is not supported, return error.
            var protocol_supported: bool = false;
            if (auth.settings.pin_uv_auth_protocols) |pin_uv_auth_protocols| {
                for (pin_uv_auth_protocols) |prot| {
                    if (prot == client_pin_param.pinUvAuthProtocol) {
                        protocol_supported = true;
                        break;
                    }
                }
            }

            if (!protocol_supported) {
                return data.StatusCodes.ctap1_err_invalid_parameter;
            }

            // If the pinRetries counter is 0, return error.
            const retries = public_data.meta.pin_retries;
            if (retries <= 0) {
                return data.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = auth.state.ecdh(client_pin_param.keyAgreement.?) catch {
                return data.StatusCodes.ctap1_err_invalid_parameter;
            };

            // Verify the data (newPinEnc || pinHashEnc)
            const new_pin_len = client_pin_param.newPinEnc.?.len;
            var msg = try allocator.alloc(u8, new_pin_len + 32);
            defer allocator.free(msg);
            std.mem.copy(u8, msg[0..new_pin_len], client_pin_param.newPinEnc.?[0..]);
            std.mem.copy(u8, msg[new_pin_len..], client_pin_param.pinHashEnc.?[0..]);

            const verified = data.State.verify(
                shared_secret[0..32].*,
                msg, // newPinEnc || pinHashEnc
                client_pin_param.pinUvAuthParam.?, // pinUvAuthParam
            );
            if (!verified) {
                return data.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // decrement pin retries
            public_data.meta.pin_retries = retries - 1;

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash1: [16]u8 = undefined;
            data.State.decrypt(
                shared_secret,
                pinHash1[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            const key = Hkdf.extract(public_data.meta.salt[0..], pinHash1[0..]);
            var secret_data = data.data.decryptSecretData(
                allocator,
                public_data.c,
                public_data.tag[0..],
                key,
                public_data.meta.nonce_ctr,
            ) catch {
                return data.StatusCodes.ctap2_err_pin_invalid;
            };

            if (!std.mem.eql(u8, pinHash1[0..], secret_data.pin_hash[0..])) {
                // The pin hashes don't match
                auth.state.regenerate(auth.resources.rand);

                if (public_data.meta.pin_retries == 0) {
                    return data.StatusCodes.ctap2_err_pin_blocked;
                    // TODO: reset authenticator -> DOOMSDAY
                } else {
                    return data.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set the pinRetries to maximum
            public_data.meta.pin_retries = 8;

            // Decrypt new pin
            var paddedNewPin: [64]u8 = undefined;
            data.State.decrypt(
                shared_secret,
                paddedNewPin[0..],
                client_pin_param.newPinEnc.?[0..],
            );
            var pnp_end: usize = 0;
            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
            const newPin = paddedNewPin[0..pnp_end];

            const npl = if (auth.settings.min_pin_length) |pl| pl else 4;
            if (newPin.len < npl) {
                return data.StatusCodes.ctap2_err_pin_policy_violation;
            }

            // TODO: support forcePINChange
            // TODO: support 15.
            // TODO: support 16.

            // Store new pin
            secret_data.pin_hash = crypto.pin.pin_hash(newPin);
            secret_data.pin_length = @intCast(u8, newPin.len);
            const pin_key = Hkdf.extract(public_data.meta.salt[0..], &secret_data.pin_hash);

            public_data.set_secret_data(&secret_data, pin_key, allocator);

            // Invalidate pinUvAuthTokens
            auth.state.resetPinUvAuthToken(auth.resources.rand);
        },
        .getPinUvAuthTokenUsingPinWithPermissions => {
            // Return error if the authenticator does not receive the
            // mandatory parameters for this command.
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.permissions == null)
            {
                return data.StatusCodes.ctap2_err_missing_parameter;
            }

            // If pinUvAuthProtocol is not supported or the permissions are 0,
            // return error.
            var protocol_supported: bool = false;
            if (auth.settings.pin_uv_auth_protocols) |pin_uv_auth_protocols| {
                for (pin_uv_auth_protocols) |prot| {
                    if (prot == client_pin_param.pinUvAuthProtocol) {
                        protocol_supported = true;
                        break;
                    }
                }
            }

            if (!protocol_supported or client_pin_param.permissions.? == 0) {
                return data.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Check if all requested premissions are valid
            const options = auth.settings.options.?;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            const mc = client_pin_param.mcPermissionSet() and (options.noMcGaPermissionsWithClientPin == true);
            const ga = client_pin_param.gaPermissionSet() and (options.noMcGaPermissionsWithClientPin == true);
            if (cm or be or lbw or acfg or mc or ga) {
                return data.StatusCodes.ctap2_err_unauthorized_permission;
            }

            // Check if the pin is blocked
            if (public_data.meta.pin_retries == 0) {
                return data.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = auth.state.ecdh(client_pin_param.keyAgreement.?) catch {
                return data.StatusCodes.ctap1_err_invalid_parameter;
            };

            // decrement pin retries
            public_data.meta.pin_retries -= 1;

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash: [16]u8 = undefined;
            data.State.decrypt(
                shared_secret,
                pinHash[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            // Derive the key from pinHash and then decrypt secret data
            const key = Hkdf.extract(public_data.meta.salt[0..], pinHash[0..]);
            var secret_data = data.data.decryptSecretData(
                allocator,
                public_data.c,
                public_data.tag[0..],
                key,
                public_data.meta.nonce_ctr,
            ) catch {
                // without valid pin/ pinHash we derive the wrong key, i.e.,
                // the encryption will fail.
                return data.StatusCodes.ctap2_err_pin_invalid;
            };
            auth.state.pin_key = key;

            if (!std.mem.eql(u8, pinHash[0..], secret_data.pin_hash[0..])) {
                // The pin hashes don't match
                auth.state.regenerate(auth.resources.rand);

                if (public_data.meta.pin_retries == 0) {
                    return data.StatusCodes.ctap2_err_pin_blocked;
                    // TODO: reset authenticator -> DOOMSDAY
                } else {
                    return data.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set retry counter to maximum
            public_data.meta.pin_retries = 8;

            // Check if user is forced to change the pin
            if (public_data.forcePINChange) |change| {
                if (change) {
                    return data.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            // Create a new pinUvAuthToken
            auth.state.resetPinUvAuthToken(auth.resources.rand);

            // Begin using the pin uv auth token
            auth.state.beginUsingPinUvAuthToken(false, auth.resources.millis());

            // Set permissions
            auth.state.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                const l = if (rpId.len > 64) 64 else rpId.len;
                std.mem.copy(u8, auth.state.rp_id_raw[0..l], rpId[0..l]);
                auth.state.rp_id = auth.state.rp_id_raw[0..l];
            }

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret = allocator.alloc(u8, 48) catch unreachable;
            var iv: [16]u8 = undefined;
            auth.resources.rand(iv[0..]);
            data.State.encrypt(
                iv,
                shared_secret,
                enc_shared_secret[0..],
                auth.state.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = enc_shared_secret,
            };
        },
        else => {
            return data.StatusCodes.ctap2_err_invalid_subcommand;
        },
    }

    // Serialize response and return
    if (client_pin_response) |resp| {
        try cbor.stringify(resp, .{}, out);
        defer resp.deinit(allocator);
    }

    return data.StatusCodes.ctap1_err_success;
}
