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
        .getCredsMetadata => {},
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
