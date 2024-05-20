const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const dt = fido.common.dt;

pub fn authenticatorClientPin(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    const retry_state = struct {
        threadlocal var ctr: u8 = 3;
        threadlocal var powerCycleState: bool = false;
    };

    const client_pin_param = cbor.parse(
        fido.ctap.request.ClientPin,
        cbor.DataItem.new(request) catch {
            return .ctap2_err_invalid_cbor;
        },
        .{},
    ) catch {
        return .ctap2_err_invalid_cbor;
    };

    var client_pin_response: ?fido.ctap.response.ClientPin = null;

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            const settings = auth.loadSettings() catch {
                return fido.ctap.StatusCodes.ctap1_err_other;
            };

            client_pin_response = .{
                .pinRetries = settings.pinRetries,
                .powerCycleState = retry_state.powerCycleState,
            };
        },
        .getUVRetries => {
            const settings = auth.loadSettings() catch {
                return fido.ctap.StatusCodes.ctap1_err_other;
            };

            client_pin_response = .{
                .uvRetries = settings.uvRetries,
            };
        },
        .getKeyAgreement => {
            const protocol = if (client_pin_param.pinUvAuthProtocol) |prot| prot else {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            };

            // return error if authenticator doesn't support the selected protocol.
            if (protocol != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            client_pin_response = .{
                .keyAgreement = auth.token.getPublicKey(),
            };
        },
        .getPinUvAuthTokenUsingUvWithPermissions => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.permissions == null or
                client_pin_param.permissions == null or
                client_pin_param.keyAgreement == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            if (client_pin_param.permissions.? == 0) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Check if all requested premissions are valid
            const options = auth.settings.options;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            // The mc and ga permissions are always considered authorized, thus they are not listed below.
            if (cm or be or lbw or acfg) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            if (!auth.uvSupported()) {
                return fido.ctap.StatusCodes.ctap2_err_not_allowed;
            }

            const settings = auth.loadSettings() catch {
                return fido.ctap.StatusCodes.ctap1_err_other;
            };

            if (settings.uvRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_uv_blocked;
            }

            var user_present = false;
            switch (auth.token.performBuiltInUv(
                true,
                auth,
                null,
                null,
                null,
            )) {
                .Blocked => return fido.ctap.StatusCodes.ctap2_err_uv_blocked,
                .Timeout => return fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
                .Denied => {
                    return fido.ctap.StatusCodes.ctap2_err_uv_invalid;
                },
                .Accepted => {},
                .AcceptedWithUp => user_present = true,
            }

            auth.token.resetPinUvAuthToken(); // invalidates existing tokens
            auth.token.beginUsingPinUvAuthToken(user_present, auth.milliTimestamp());

            auth.token.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                auth.token.setRpId(rpId.get());
            }

            // Obtain the shared secret
            const shared_secret = auth.token.ecdh(
                client_pin_param.keyAgreement.?,
                auth.allocator,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };
            defer auth.allocator.free(shared_secret);

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret: [48]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret,
                enc_shared_secret[0..],
                auth.token.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = (dt.ABS48B.fromSlice(&enc_shared_secret) catch unreachable).?,
            };
        },
        else => {
            return fido.ctap.StatusCodes.ctap2_err_invalid_subcommand;
        },
    }

    // Serialize response and return
    if (client_pin_response) |resp| {
        cbor.stringify(resp, .{}, out.writer()) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}
