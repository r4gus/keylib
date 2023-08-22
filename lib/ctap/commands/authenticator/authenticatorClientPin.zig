const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

pub fn authenticatorClientPin(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
    command: []const u8,
) !fido.ctap.StatusCodes {
    const retry_state = struct {
        threadlocal var ctr: u8 = 3;
        threadlocal var powerCycleState: bool = false;
    };

    const client_pin_param = try cbor.parse(
        fido.ctap.request.ClientPin,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = auth.allocator,
        },
    );
    defer client_pin_param.deinit(auth.allocator);

    var client_pin_response: ?fido.ctap.response.ClientPin = null;

    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("authenticatorClientPin: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer settings.deinit(auth.allocator);
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("authenticatorClientPin: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            client_pin_response = .{
                .pinRetries = settings.retries,
                .powerCycleState = retry_state.powerCycleState,
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
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

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

            var already_set = settings.pin != null;
            if (already_set) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(
                client_pin_param.keyAgreement.?,
                auth.allocator,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };
            defer auth.allocator.free(shared_secret);

            // Verify parameters
            const verified = prot.verify(
                shared_secret,
                client_pin_param.newPinEnc.?,
                client_pin_param.pinUvAuthParam.?, // pinUvAuthParam
                auth.allocator,
            );
            if (!verified) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // Decrypt new pin
            var paddedNewPin: [64]u8 = undefined;
            prot.decrypt(
                shared_secret,
                paddedNewPin[0..],
                client_pin_param.newPinEnc.?[0..],
            );
            var pnp_end: usize = 0;
            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
            const newPin = paddedNewPin[0..pnp_end];

            const npl = if (auth.settings.minPINLength) |pl| pl else 4;

            // Count the number of code points. We must then check the required
            // length of the password against the code point length.
            const _code_points = std.unicode.utf8CountCodepoints(newPin) catch {
                std.log.err("authenticatorClientPin (setPin): invalid utf8 string", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            };
            const code_points: u8 = @as(u8, @intCast(_code_points));

            if (code_points < npl) {
                std.log.err("authenticatorClientPin (setPin): length insufficient, expected {d} got {d}", .{ npl, code_points });
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            if (auth.callbacks.validate_pin_constraints) |vpc| {
                // Check additional PIN constraints
                if (!vpc(newPin)) {
                    std.log.err("authenticatorClientPin (setPin): pin constraint violated", .{});
                    return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            // Store new pin
            const ph = fido.ctap.pinuv.hash(newPin);
            try settings.setPin(ph, code_points, auth.secret.enc, auth.callbacks.rand);
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("authenticatorClientPin (setPin): unable to update settings ({any})", .{err});
                return err;
            };
        },
        .changePIN => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

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
            if (settings.retries <= 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(
                client_pin_param.keyAgreement.?,
                auth.allocator,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };
            defer auth.allocator.free(shared_secret);

            // Verify the data (newPinEnc || pinHashEnc)
            const new_pin_len = client_pin_param.newPinEnc.?.len;
            const pin_hash_enc_len = client_pin_param.pinHashEnc.?.len;
            var msg = try auth.allocator.alloc(u8, new_pin_len + pin_hash_enc_len);
            defer auth.allocator.free(msg);
            std.mem.copy(u8, msg[0..new_pin_len], client_pin_param.newPinEnc.?[0..]);
            std.mem.copy(u8, msg[new_pin_len..], client_pin_param.pinHashEnc.?[0..]);

            const verified = prot.verify(
                shared_secret,
                msg, // newPinEnc || pinHashEnc
                client_pin_param.pinUvAuthParam.?, // pinUvAuthParam
                auth.allocator,
            );
            if (!verified) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // decrement pin retries
            settings.retries -= 1;
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("authenticatorClientPin (updatePin): unable to update settings ({any})", .{err});
                return err;
            };

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash1: [16]u8 = undefined;
            prot.decrypt(
                shared_secret,
                pinHash1[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            if (settings.pin == null) {
                return fido.ctap.StatusCodes.ctap2_err_pin_not_set;
            }

            var cp: u8 = 0;
            const pinHash2 = try settings.getPin(auth.secret.enc, &cp);

            if (!std.mem.eql(u8, pinHash1[0..], pinHash2[0..16])) {
                // The pin hashes don't match
                if (retry_state.ctr > 0) retry_state.ctr -= 1;

                prot.regenerate();

                if (settings.retries == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                } else if (retry_state.ctr == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set the pinRetries to maximum
            settings.retries = 8;
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("changePIN: unable to update settings ({any})", .{err});
                return err;
            };

            // Decrypt new pin
            var paddedNewPin: [64]u8 = undefined;
            prot.decrypt(
                shared_secret,
                paddedNewPin[0..],
                client_pin_param.newPinEnc.?[0..],
            );
            var pnp_end: usize = 0;
            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
            const newPin = paddedNewPin[0..pnp_end];

            const npl = if (auth.settings.minPINLength) |pl| pl else 4;

            // Count the number of code points. We must then check the required
            // length of the password against the code point length.
            const _code_points = std.unicode.utf8CountCodepoints(newPin) catch {
                std.log.err("authenticatorClientPin (setPin): invalid utf8 string", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            };
            const code_points: u8 = @as(u8, @intCast(_code_points));

            if (code_points < npl) {
                std.log.err("authenticatorClientPin (setPin): length insufficient, expected {d} got {d}", .{ npl, code_points });
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            const ph = fido.ctap.pinuv.hash(newPin);

            // Validate forePINChange
            if (settings.force_pin_change) {
                // Hash of new pin must not be the same as the old hash
                if (std.mem.eql(u8, pinHash2[0..], &ph)) {
                    std.log.err("authenticatorClientPin (changePin): new and old pin must differ", .{});
                    return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            if (auth.callbacks.validate_pin_constraints) |vpc| {
                // Check additional PIN constraints
                if (!vpc(newPin)) {
                    std.log.err("authenticatorClientPin (changePin): pin constraint violated", .{});
                    return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
                }
            }

            try settings.setPin(ph, code_points, auth.secret.enc, auth.callbacks.rand);
            settings.force_pin_change = false;
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("authenticatorClientPin (changePin): unable to update settings ({any})", .{err});
                return err;
            };

            // Invalidate all pinUvAuthTokens
            if (auth.token.one) |*one| {
                one.resetPinUvAuthToken();
            }
            if (auth.token.two) |*two| {
                two.resetPinUvAuthToken();
            }
        },
        .getPinUvAuthTokenUsingPinWithPermissions => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

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
            if (settings.retries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // Obtain the shared secret
            const shared_secret = prot.ecdh(
                client_pin_param.keyAgreement.?,
                auth.allocator,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };
            defer auth.allocator.free(shared_secret);

            // decrement pin retries
            settings.retries -= 1;
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("getPinUvAuthTokenUsingPinWithPermissions: unable to update settings ({any})", .{err});
                return err;
            };

            // Decrypt pinHashEnc and match against stored pinHash
            var pinHash1: [16]u8 = undefined;
            prot.decrypt(
                shared_secret,
                pinHash1[0..],
                client_pin_param.pinHashEnc.?[0..],
            );

            var cp: u8 = 0;
            const pinHash2 = try settings.getPin(auth.secret.enc, &cp);

            if (!std.mem.eql(u8, pinHash1[0..], pinHash2[0..16])) {
                // The pin hashes don't match
                if (retry_state.ctr > 0) retry_state.ctr -= 1;

                prot.regenerate();

                if (settings.retries == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                } else if (retry_state.ctr == 0) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
                } else {
                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                }
            }

            // Set retry counter to maximum
            settings.retries = 8;
            settings.updateMac(&auth.secret.mac);
            auth.callbacks.updateSettings(&settings, auth.allocator) catch |err| {
                std.log.err("getPinUvAuthTokenUsingPinWithPermissions: unable to update settings ({any})", .{err});
                return err;
            };

            // Check if user is forced to change the pin
            if (settings.force_pin_change) {
                std.log.err("authenticatorClientPin (getPinUvAuthTokenUsingPinWithPermissions): pin change required", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            // Create a new pinUvAuthToken
            prot.resetPinUvAuthToken();

            // Begin using the pin uv auth token
            prot.beginUsingPinUvAuthToken(false, auth.callbacks.millis());

            // Set permissions
            prot.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                prot.setRpId(rpId);
            }

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret = auth.allocator.alloc(u8, 48) catch unreachable;
            prot.encrypt(
                prot,
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
