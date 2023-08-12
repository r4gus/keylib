const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

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
        auth.allocator.free(auth.credential_list.?.list);
        auth.credential_list = null;
        return fido.ctap.StatusCodes.ctap2_err_not_allowed;
    }

    // Fetch authenticator settings to get master secret
    var settings = if (auth.callbacks.getEntry("Settings")) |settings| settings else {
        std.log.err("Unable to fetch Settings", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    var _ms = if (settings.getField("Secret", auth.callbacks.millis())) |ms| ms else {
        std.log.err("Secret field missing in Settings", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    const ms: fido.ctap.crypto.master_secret.MasterSecret = _ms[0..fido.ctap.crypto.master_secret.MS_LEN].*;

    // Fetch next credential id
    const id = auth.credential_list.?.list[auth.credential_list.?.credentialCounter];
    auth.credential_list.?.credentialCounter += 1;

    // Fetch the credential based on credential id and update the return data
    var user: ?fido.common.User = null;
    if (auth.callbacks.getEntry(id.raw[0..])) |entry| {
        // Seems like this is a discoverable credential, because we
        // just discovered it :)
        auth.credential_list.?.authData.signCount = @as(u32, @intCast(entry.times.usageCount));
        entry.times.usageCount += 1;

        if (auth.credential_list.?.authData.flags.uv == 1) {
            // publicKeyCredentialUserEntity MUST NOT be returned if user verification
            // was not done by the authenticator in the original authenticatorGetAssertion call
            const user_id = entry.getField("UserId", auth.callbacks.millis());
            if (user_id) |uid| {
                // User identifiable information (name, DisplayName, icon)
                // inside the publicKeyCredentialUserEntity MUST NOT be returned
                // if user verification is not done by the authenticator
                user = .{ .id = uid, .name = null, .displayName = null };
            } else {
                std.log.warn(
                    "UserId field missing for id: {s}",
                    .{std.fmt.fmtSliceHexUpper(id.raw[0..])},
                );
            }
        }
    } else {
        std.log.warn(
            "Unable to load credential with id: {s}",
            .{std.fmt.fmtSliceHexUpper(id.raw[0..])},
        );
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    // select algorithm based on credential
    const algorithm = id.getAlg();
    var alg: ?fido.ctap.crypto.SigAlg = null;
    for (auth.algorithms) |_alg| blk: {
        if (algorithm == _alg.alg) {
            alg = _alg;
            break :blk;
        }
    }

    if (alg == null) {
        std.log.err("Unknown algorithm for credential with id: {s}", .{std.fmt.fmtSliceHexLower(&id.raw)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    }

    const seed = id.deriveSeed(ms);
    const key_pair = if (alg.?.create_det(
        &seed,
        auth.allocator,
    )) |kp| kp else return fido.ctap.StatusCodes.ctap1_err_other;
    defer {
        auth.allocator.free(key_pair.cose_public_key);
        auth.allocator.free(key_pair.raw_private_key);
    }

    // Sign the data
    var authData = std.ArrayList(u8).init(auth.allocator);
    defer authData.deinit();
    try auth.credential_list.?.authData.encode(authData.writer());

    const sig = if (alg.?.sign(
        key_pair.raw_private_key,
        &.{ authData.items, &auth.credential_list.?.clientDataHash },
        auth.allocator,
    )) |signature| signature else {
        std.log.err("signature creation failed for credential with id: {s}", .{std.fmt.fmtSliceHexLower(&id.raw)});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    defer auth.allocator.free(sig);

    const gar = fido.ctap.response.GetAssertion{
        .credential = .{
            .type = .@"public-key",
            .id = &id.raw,
        },
        .authData = authData.items,
        .signature = sig,
        .user = user,
    };

    try auth.callbacks.persist();

    try cbor.stringify(gar, .{ .allocator = auth.allocator }, out);

    auth.credential_list.?.time_stamp = auth.callbacks.millis();

    return .ctap1_err_success;
}
