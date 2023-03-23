const std = @import("std");
const cbor = @import("zbor");

const Authenticator = @import("../Authenticator.zig");
const data = @import("../data.zig");
const crypto = @import("../crypto.zig");

pub fn authenticator_get_assertion(
    auth: *Authenticator,
    public_data: *data.PublicData,
    get_assertion_param: *const data.get_assertion.GetAssertionParam,
    out: anytype,
    allocator: std.mem.Allocator,
) !data.StatusCodes {
    // decode secret data
    var secret_data = data.data.decryptSecretData(
        allocator,
        public_data.c,
        public_data.tag[0..],
        auth.state.pin_key.?,
        public_data.meta.nonce_ctr,
    ) catch {
        return data.StatusCodes.ctap2_err_pin_invalid;
    };

    // locate all denoted credentials present on this
    // authenticator and bound to the specified rpId.
    var ctx_and_mac: ?[]const u8 = null;
    if (get_assertion_param.allowList) |creds| {
        for (creds) |cred| {
            if (cred.id.len < crypto.context.cred_id_len) continue;

            if (crypto.context.verify_cred_id(
                secret_data.master_secret,
                cred.id[0..crypto.context.cred_id_len].*,
                get_assertion_param.rpId,
            )) {
                ctx_and_mac = cred.id[0..];
                break;
            }
        }
    }

    if (ctx_and_mac == null) {
        return data.StatusCodes.ctap2_err_no_credentials;
    }

    // Get up flag
    const opt_up = if (get_assertion_param.options) |options| options.up else true;
    var up: bool = auth.state.user_present;

    if (opt_up) {
        // Check user presence
        if (!up) {
            up = auth.resources.request_permission(null, null);
        }
        if (!up) {
            return data.StatusCodes.ctap2_err_operation_denied;
        }

        // clear permissions
        auth.state.user_present = false;
        auth.state.user_verified = false;
        auth.state.permissions = 0x10;
    } else {
        // 'pre-flight'
        up = false;
    }

    // Return signature
    var ad = data.make_credential.attestation.AuthData{
        .rp_id_hash = undefined,
        .flags = .{
            .up = if (up) 1 else 0,
            .rfu1 = 0,
            .uv = 1,
            .rfu2 = 0,
            .at = 0,
            .ed = 0,
        },
        .sign_count = secret_data.sign_ctr,
        // attestedCredentialData are excluded
    };
    secret_data.sign_ctr += 1;
    std.crypto.hash.sha2.Sha256.hash(get_assertion_param.rpId, &ad.rp_id_hash, .{});
    var authData = std.ArrayList(u8).init(allocator);
    defer authData.deinit();
    try ad.encode(authData.writer());

    // 12. Sign the clientDataHash along with authData with the
    // selected credential.
    var key_pair = crypto.algorithms.SignatureAlgorithmKeyPair.new(
        secret_data.master_secret,
        ctx_and_mac.?[0..crypto.context.context_len].*,
    ) catch unreachable;

    const sig = key_pair.sign(authData.items, get_assertion_param.clientDataHash);

    const get_assertion_response = data.get_assertion.GetAssertionResponse{
        .credential = .{
            .type = "public-key",
            .id = ctx_and_mac.?,
        },
        .authData = authData.items,
        .signature = sig,
    };

    try cbor.stringify(get_assertion_response, .{}, out);

    // Sign counter has been increased
    public_data.set_secret_data(&secret_data, auth.state.pin_key.?, allocator);

    return data.StatusCodes.ctap1_err_success;
}
