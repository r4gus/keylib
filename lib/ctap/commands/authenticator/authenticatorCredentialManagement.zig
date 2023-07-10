const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

pub fn authenticatorCredentialManagement(
    auth: *fido.ctap.authenticator.Authenticator,
    out: anytype,
    command: []const u8,
) !fido.ctap.StatusCodes {
    const cmReq = try cbor.parse(
        fido.ctap.request.CredentialManagement,
        try cbor.DataItem.new(command[1..]),
        .{
            .allocator = auth.allocator,
        },
    );
    defer cmReq.deinit(auth.allocator);

    var cmResp: fido.ctap.response.CredentialManagement = .{};
    defer cmResp.deinit(auth.allocator);

    switch (cmReq.subCommand) {
        .getCredsMetadata => {
            if (cmReq.pinUvAuthParam == null) {
                std.log.err("authenticatorCredentialManagement: pinUvAuthParam missing", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_required;
            }

            if (!auth.pinUvAuthProtocolSupported(cmReq.pinUvAuthProtocol)) {
                std.log.err("authenticatorCredentialManagement: unsupported pinUvAuthProtocol version ({any})", .{cmReq.pinUvAuthProtocol});
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            var prot = switch (cmReq.pinUvAuthProtocol.?) {
                .V1 => &auth.token.one.?,
                .V2 => &auth.token.two.?,
            };

            if (!prot.verify_token("\x01", cmReq.pinUvAuthParam.?, auth.allocator)) {
                std.log.err("authenticatorCredentialManagement: token verification failed", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if ((prot.permissions & 0x04) != 0x04 or prot.rp_id != null) {
                // cm permission must be set and NO associated permissions RP ID.
                std.log.err("authenticatorCredentialManagement: wrong permission or associated rpId", .{});
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            cmResp.existingResidentCredentialsCount = if (auth.callbacks.getEntries()) |entries| @intCast(entries.len) else 0;
            cmResp.maxPossibleRemainingResidentCredentialsCount = 99;
        },
        .enumerateRPsBegin => {},
        .enumerateRPsGetNextRP => {},
        .enumerateCredentialsBegin => {},
        .enumerateCredentialsGetNextCredential => {},
        .deleteCredential => {},
        .updateUserInformation => {},
    }

    try cbor.stringify(cmResp, .{}, out);
    return fido.ctap.StatusCodes.ctap1_err_success;
}
