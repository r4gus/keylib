const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const uuid = @import("uuid");
const helper = @import("helper.zig");
const deriveMacKey = fido.ctap.crypto.master_secret.deriveMacKey;
const deriveEncKey = fido.ctap.crypto.master_secret.deriveEncKey;

pub fn authenticatorGetNextAssertion(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
) !fido.ctap.StatusCodes {
    if (auth.credential_list == null) {
        return fido.ctap.StatusCodes.ctap2_err_not_allowed;
    }

    if (auth.credential_list.?.credentialCounter >= auth.credential_list.?.list.len or
        (auth.callbacks.millis() - auth.credential_list.?.time_stamp) >= 30000)
    {
        auth.credential_list.?.deinit(auth.allocator);
        auth.credential_list = null;
        return fido.ctap.StatusCodes.ctap2_err_not_allowed;
    }

    var settings = auth.callbacks.readSettings(auth.allocator) catch |err| {
        std.log.err("authenticatorGetNextAssertion: Unable to fetch Settings ({any})", .{err});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer settings.deinit(auth.allocator);
    if (!settings.verifyMac(&auth.secret.mac)) {
        std.log.err("authenticatorGetNextAssertion: Settings MAC validation unsuccessful", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const ms = try settings.getSecret(auth.secret.enc);

    // Fetch next credential id
    var cred = auth.credential_list.?.list[auth.credential_list.?.credentialCounter];
    auth.credential_list.?.credentialCounter += 1;

    // Fetch the credential based on credential id and update the return data
    var user: ?fido.common.User = null;

    // Seems like this is a discoverable credential, because we
    // just discovered it :)
    auth.credential_list.?.authData.signCount = @as(u32, @intCast(cred.sign_count));
    cred.sign_count += 1;

    if (auth.credential_list.?.authData.flags.uv == 1) {
        // publicKeyCredentialUserEntity MUST NOT be returned if user verification
        // was not done by the authenticator in the original authenticatorGetAssertion call

        // User identifiable information (name, DisplayName, icon)
        // inside the publicKeyCredentialUserEntity MUST NOT be returned
        // if user verification is not done by the authenticator
        user = .{
            .id = cred.user_id,
            .name = cred.user_name,
            .displayName = cred.user_display_name,
        };
    }

    // select algorithm based on credential
    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (auth.algorithms) |_alg| blk: {
        if (cred.alg == _alg.alg) {
            alg = _alg;
            break :blk;
        }
    }

    if (alg == null) {
        std.log.err("Unknown algorithm for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred._id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const enc_key = deriveEncKey(ms);
    const raw_key = try cred.getPrivateKey(enc_key, auth.allocator);
    defer auth.allocator.free(raw_key);

    // Sign the data
    var authData = std.ArrayList(u8).init(auth.allocator);
    defer authData.deinit();
    try auth.credential_list.?.authData.encode(authData.writer());

    const sig = if (alg.?.sign(
        raw_key,
        &.{ authData.items, &auth.credential_list.?.clientDataHash },
        auth.allocator,
    )) |signature| signature else {
        std.log.err("signature creation failed for credential with id: {s}", .{std.fmt.fmtSliceHexLower(cred._id)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(sig);

    const uid = try uuid.urn.deserialize(cred._id[0..]);
    const gar = fido.ctap.response.GetAssertion{
        .credential = .{
            .type = .@"public-key",
            .id = std.mem.asBytes(&uid),
        },
        .authData = authData.items,
        .signature = sig,
        .user = user,
    };

    try auth.callbacks.persist();

    const mac_key = deriveMacKey(ms);
    cred.updateMac(&mac_key);
    auth.callbacks.updateCred(&cred, auth.allocator) catch |err| {
        std.log.err("authenticatorGetAssertion: unable to update credential ({any})", .{err});
        return err;
    };

    try cbor.stringify(gar, .{ .allocator = auth.allocator }, out);

    auth.credential_list.?.time_stamp = auth.callbacks.millis();

    return .ctap1_err_success;
}
