const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

pub fn authenticatorClientPin(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
    command: []const u8,
) !fido.ctap.StatusCodes {
    const client_pin_param = try cbor.parse(
        fido.ctap.request.ClientPin,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = auth.allocator,
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
    defer client_pin_param.deinit(auth.allocator);

    var client_pin_response: ?fido.ctap.response.ClientPin = null;

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            client_pin_response = .{
                .pinRetries = try auth.callbacks.get_retries(),
                .powerCycleState = false,
            };
        },
        .getKeyAgreement => {
            const protocol = if (client_pin_param.pinUvAuthProtocol) |prot| prot else {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            };

            // return error if authenticator doesn't support the selected protocol.
            if (!auth.pinUvAuthProtocolSupported(client_pin_param.pinUvAuthProtocol.?)) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            var prot = switch (protocol) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            client_pin_response = .{
                .keyAgreement = prot.getPublicKey(),
            };
        },
        .setPIN => {
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.newPinEnc == null or
                client_pin_param.pinUvAuthParam == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (!auth.pinUvAuthProtocolSupported(client_pin_param.pinUvAuthProtocol.?)) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            var prot = switch (client_pin_param.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            var already_set = true;
            _ = auth.callbacks.loadCurrentStoredPIN() catch |e| {
                if (e == error.DoesNotExist) {
                    already_set = false;
                } else { // unexpected error
                    return fido.ctap.StatusCodes.ctap1_err_other;
                }
            };

            if (already_set) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(client_pin_param.keyAgreement.?) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // Verify parameters
            const verified = fido.ctap.pinuv.PinUvAuth.verify(
                shared_secret[0..32].*,
                client_pin_param.newPinEnc.?,
                client_pin_param.pinUvAuthParam.?, // pinUvAuthParam
            );
            if (!verified) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // Decrypt new pin
            var paddedNewPin: [64]u8 = undefined;
            fido.ctap.pinuv.PinUvAuth.decrypt(
                shared_secret,
                paddedNewPin[0..],
                client_pin_param.newPinEnc.?[0..],
            );
            var pnp_end: usize = 0;
            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
            const newPin = paddedNewPin[0..pnp_end];

            const npl = if (auth.settings.minPINLength) |pl| pl else 4;
            if (newPin.len < npl) {
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            // Store new pin
            const ph = fido.ctap.pinuv.hash(newPin);
            auth.callbacks.storeCurrentStoredPIN(ph);
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
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            // If pinUvAuthProtocol is not supported, return error.
            if (!auth.pinUvAuthProtocolSupported(client_pin_param.pinUvAuthProtocol.?)) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            var prot = switch (client_pin_param.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            // If the pinRetries counter is 0, return error.
            var retries = try auth.callbacks.get_retries();
            if (retries <= 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(client_pin_param.keyAgreement.?) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // Verify the data (newPinEnc || pinHashEnc)
            const new_pin_len = client_pin_param.newPinEnc.?.len;
            var msg = try auth.allocator.alloc(u8, new_pin_len + 32);
            defer auth.allocator.free(msg);
            std.mem.copy(u8, msg[0..new_pin_len], client_pin_param.newPinEnc.?[0..]);
            std.mem.copy(u8, msg[new_pin_len..], client_pin_param.pinHashEnc.?[0..]);

            const verified = fido.ctap.pinuv.PinUvAuth.verify(
                shared_secret[0..32].*,
                msg, // newPinEnc || pinHashEnc
                client_pin_param.pinUvAuthParam.?, // pinUvAuthParam
            );
            if (!verified) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // decrement pin retries
            retries = retries - 1;
            auth.callbacks.set_retries(retries);

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash1: [16]u8 = undefined;
            fido.ctap.pinuv.PinUvAuth.decrypt(
                shared_secret,
                pinHash1[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            const pinHash2 = auth.callbacks.loadCurrentStoredPIN() catch {
                return fido.ctap.StatusCodes.ctap2_err_pin_not_set;
            };

            if (!std.mem.eql(u8, pinHash1[0..], pinHash2[0..16])) {
                // The pin hashes don't match
                prot.regenerate(auth.callbacks.rand);

                if (retries == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                    // TODO: reset authenticator -> DOOMSDAY
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set the pinRetries to maximum
            retries = 8;
            auth.callbacks.set_retries(retries);

            // Decrypt new pin
            var paddedNewPin: [64]u8 = undefined;
            fido.ctap.pinuv.PinUvAuth.decrypt(
                shared_secret,
                paddedNewPin[0..],
                client_pin_param.newPinEnc.?[0..],
            );
            var pnp_end: usize = 0;
            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
            const newPin = paddedNewPin[0..pnp_end];

            const npl = if (auth.settings.minPINLength) |pl| pl else 4;
            if (newPin.len < npl) {
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            const ph = fido.ctap.pinuv.hash(newPin);

            // Validate forePINChange
            if (auth.settings.forcePINChange) |fpc| {
                // Hash of new pin must not be the same as the old hash
                if (fpc and std.mem.eql(u8, pinHash2[0..], &ph)) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            auth.callbacks.storePINCodePointLength(@intCast(u8, pnp_end));
            auth.settings.forcePINChange = false;

            // Store new pin
            auth.callbacks.storeCurrentStoredPIN(ph);

            // Invalidate all pinUvAuthTokens
            if (auth.token.one) |*one| {
                one.resetPinUvAuthToken(auth.callbacks.rand);
            }
            if (auth.token.two) |*two| {
                two.resetPinUvAuthToken(auth.callbacks.rand);
            }
        },
        .getPinUvAuthTokenUsingPinWithPermissions => {
            // Return error if the authenticator does not receive the
            // mandatory parameters for this command.
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.permissions == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            // If pinUvAuthProtocol is not supported or the permissions are 0,
            // return error.
            if (!auth.pinUvAuthProtocolSupported(client_pin_param.pinUvAuthProtocol.?)) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            var prot = switch (client_pin_param.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            // Check if all requested premissions are valid
            const options = auth.settings.options.?;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            const mc = client_pin_param.mcPermissionSet() and (options.noMcGaPermissionsWithClientPin == true);
            const ga = client_pin_param.gaPermissionSet() and (options.noMcGaPermissionsWithClientPin == true);
            if (cm or be or lbw or acfg or mc or ga) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            // Check if the pin is blocked
            var retries = try auth.callbacks.get_retries();
            if (retries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(client_pin_param.keyAgreement.?) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // decrement pin retries
            retries = retries - 1;
            auth.callbacks.set_retries(retries);

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash1: [16]u8 = undefined;
            fido.ctap.pinuv.PinUvAuth.decrypt(
                shared_secret,
                pinHash1[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            const pinHash2 = try auth.callbacks.loadCurrentStoredPIN();

            if (!std.mem.eql(u8, pinHash1[0..], pinHash2[0..16])) {
                // The pin hashes don't match
                prot.regenerate(auth.callbacks.rand);

                if (retries == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                    // TODO: reset authenticator -> DOOMSDAY
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set retry counter to maximum
            retries = 8;
            auth.callbacks.set_retries(retries);

            // Check if user is forced to change the pin
            if (auth.settings.forcePINChange) |change| {
                if (change) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            // Create a new pinUvAuthToken
            prot.resetPinUvAuthToken(auth.callbacks.rand);

            // Begin using the pin uv auth token
            prot.beginUsingPinUvAuthToken(false, auth.callbacks.millis());

            // Set permissions
            prot.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                const l = if (rpId.len > 64) 64 else rpId.len;
                std.mem.copy(u8, prot.rp_id_raw[0..l], rpId[0..l]);
                prot.rp_id = prot.rp_id_raw[0..l];
            }

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret = auth.allocator.alloc(u8, 48) catch unreachable;
            var iv: [16]u8 = undefined;
            auth.callbacks.rand(iv[0..]);
            fido.ctap.pinuv.PinUvAuth.encrypt(
                iv,
                shared_secret,
                enc_shared_secret[0..],
                prot.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = enc_shared_secret,
            };
        },
        else => {
            return fido.ctap.StatusCodes.ctap2_err_invalid_subcommand;
        },
    }

    // Serialize response and return
    if (client_pin_response) |resp| {
        try cbor.stringify(resp, .{}, out);
        defer resp.deinit(auth.allocator);
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}
