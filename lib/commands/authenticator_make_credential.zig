const std = @import("std");
const cbor = @import("zbor");

const Authenticator = @import("../Authenticator.zig");
const data = @import("../data.zig");
const crypto = @import("../crypto.zig");

pub fn authenticator_make_credential(
    auth: *Authenticator,
    public_data: *data.PublicData,
    make_credential_param: *const data.make_credential.MakeCredentialParam,
    out: anytype,
    allocator: std.mem.Allocator,
) !data.StatusCodes {

    // Check for a valid COSEAlgorithmIdentifier value
    var alg: ?cbor.cose.Algorithm = null;
    for (make_credential_param.pubKeyCredParams) |param| outer_alg: {
        for (auth.sig_alg) |algorithm| {
            if (param.alg == algorithm) {
                alg = algorithm;
                break :outer_alg;
            }
        }
    }

    if (alg == null) {
        return data.StatusCodes.ctap2_err_unsupported_algorithm;
    }

    // Process all given options
    if (make_credential_param.options) |options| {
        // we let the RP store the context for each credential.
        // we also don't support built in user verification
        if ((options.rk != null and options.rk.?) or (options.uv != null and options.uv.?)) {
            return data.StatusCodes.ctap2_err_unsupported_option;
        }
    }

    // Request permission from the user
    if (!auth.state.user_present and !auth.resources.request_permission(
        &make_credential_param.user,
        &make_credential_param.rp,
    )) {
        return data.StatusCodes.ctap2_err_operation_denied;
    }

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

    // check exclude list: don't allow to create two credentials for the same service
    if (make_credential_param.excludeList) |excludes| {
        for (excludes) |cred| {
            if (cred.id.len < crypto.context.cred_id_len) continue;

            if (crypto.context.verify_cred_id(
                secret_data.master_secret,
                cred.id[0..crypto.context.cred_id_len].*,
                make_credential_param.rp.id,
            )) {
                return data.StatusCodes.ctap2_err_credential_excluded;
            }
        }
    }

    // Generate a new credential key pair for the algorithm specified.
    const context = crypto.context.newContext(auth.resources.rand, alg.?);
    var key_pair = crypto.algorithms.SignatureAlgorithmKeyPair.new(
        secret_data.master_secret,
        context,
    ) catch unreachable;

    // Create a new credential id
    const cred_id = crypto.context.make_cred_id(
        secret_data.master_secret,
        context,
        make_credential_param.rp.id,
    );

    // Generate an attestation statement for the newly-created
    var auth_data = data.make_credential.attestation.AuthData{
        .rp_id_hash = undefined,
        .flags = .{
            .up = 1,
            .rfu1 = 0,
            .uv = 1,
            .rfu2 = 0,
            .at = 1,
            .ed = 0,
        },
        .sign_count = secret_data.sign_ctr,
        .attested_credential_data = .{
            .aaguid = auth.settings.aaguid,
            .credential_length = crypto.context.cred_id_len,
            .credential_id = &cred_id,
            .credential_public_key = key_pair.to_cose(),
        },
    };

    secret_data.sign_ctr += 1;

    // Calculate the SHA-256 hash of the rpId (base url).
    std.crypto.hash.sha2.Sha256.hash(
        make_credential_param.rp.id,
        &auth_data.rp_id_hash,
        .{},
    );

    // Create attestation statement
    var authData = std.ArrayList(u8).init(allocator);
    defer authData.deinit();
    try auth_data.encode(authData.writer());

    var stmt: ?data.make_credential.attestation.AttStmt = null;
    if (auth.attestation_type == .Self) {
        const sig = key_pair.sign(authData.items, make_credential_param.clientDataHash);

        stmt = .{ .@"packed" = .{
            .alg = key_pair.algorithm(),
            .sig = sig,
        } };
    } else {
        stmt = .{ .none = .{} };
    }

    const attestation_object = data.make_credential.attestation.AttestationObject{
        .fmt = data.make_credential.attestation.Fmt.@"packed",
        .authData = auth_data,
        .attStmt = stmt.?,
    };

    try cbor.stringify(attestation_object, .{ .allocator = allocator }, out);

    // Sign counter has been increased
    public_data.set_secret_data(&secret_data, auth.state.pin_key.?, allocator);

    return data.StatusCodes.ctap1_err_success;
}
