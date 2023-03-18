const std = @import("std");
const cbor = @import("zbor");

const Authenticator = @import("../Authenticator.zig");
const data = @import("../data.zig");
const crypto = @import("../crypto.zig");

pub fn authenticator_make_credential(
    auth: *Authenticator,
    public_data: *data.PublicData,
    out: anytype,
    command: []const u8,
    allocator: std.mem.Allocator,
) !data.StatusCodes {
    const make_credential_param = try cbor.parse(
        data.make_credential.MakeCredentialParam,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = allocator,
            .field_settings = &.{
                .{ .name = "clientDataHash", .alias = "1", .options = .{} },
                .{ .name = "rp", .alias = "2", .options = .{} },
                .{ .name = "user", .alias = "3", .options = .{} },
                .{ .name = "pubKeyCredParams", .alias = "4", .options = .{} },
                .{ .name = "excludeList", .alias = "5", .options = .{} },
                .{ .name = "options", .alias = "7", .options = .{} },
                .{ .name = "pinUvAuthParam", .alias = "8", .options = .{} },
                .{ .name = "pinUvAuthProtocol", .alias = "9", .options = .{} },
            },
        },
    );
    defer make_credential_param.deinit(allocator);

    // Return error if the authenticator does not receive the
    // mandatory parameters for this command.
    if (make_credential_param.pinUvAuthProtocol == null) {
        return data.StatusCodes.ctap2_err_missing_parameter;
    }

    // Return error if a zero length pinUvAuthParam is receieved
    if (make_credential_param.pinUvAuthParam == null) {
        if (!auth.resources.request_permission(
            &make_credential_param.user,
            &make_credential_param.rp,
        )) {
            return data.StatusCodes.ctap2_err_operation_denied;
        } else {
            return data.StatusCodes.ctap2_err_pin_invalid;
        }
    }

    // If pinUvAuthProtocol is not supported, return error.
    var protocol_supported: bool = false;
    for (auth.settings.pin_uv_auth_protocols) |prot| {
        if (prot == make_credential_param.pinUvAuthProtocol.?) {
            protocol_supported = true;
            break;
        }
    }

    if (!protocol_supported) {
        return data.StatusCodes.ctap1_err_invalid_parameter;
    }

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

    alg = cbor.cose.Algorithm.Es256;
    if (alg == null) {
        return data.StatusCodes.ctap2_err_unsupported_algorithm;
    }

    // Process all given options
    if (make_credential_param.options) |options| {
        // we let the RP store the context for each credential.
        // we also don't support built in user verification
        if (options.rk or options.uv) {
            return data.StatusCodes.ctap2_err_unsupported_option;
        }
    }

    // Enforce user verification
    if (!auth.state.in_use) { // TODO: maybe just switch with getUserVerifiedFlagValue() call
        return data.StatusCodes.ctap2_err_pin_token_expired;
    }

    if (!data.State.verify(
        auth.state.pin_token,
        make_credential_param.clientDataHash,
        make_credential_param.pinUvAuthParam.?,
    )) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    if (auth.state.permissions & 0x01 == 0) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    if (auth.state.rp_id) |rpId| {
        const rpId2 = make_credential_param.rp.id;
        if (!std.mem.eql(u8, rpId, rpId2)) {
            return data.StatusCodes.ctap2_err_pin_auth_invalid;
        }
    }

    if (!auth.state.getUserVerifiedFlagValue()) {
        return data.StatusCodes.ctap2_err_pin_auth_invalid;
    }

    // TODO: If the pinUvAuthToken does not have a permissions RP ID associated:
    // Associate the request’s rp.id parameter value with the pinUvAuthToken as its permissions RP ID.

    // TODO: check exclude list

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

    return data.StatusCodes.ctap1_err_success;
}
