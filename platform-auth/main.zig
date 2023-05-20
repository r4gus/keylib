const std = @import("std");
const fido = @import("fido");

const callbacks = @import("callbacks.zig");
const ctaphid = @import("ctaphid.zig");

const USB_PATH = "/dev/fido";

pub fn main() !void {
    // We expect an usb gadget at USB_PATH, this will
    // be used ipc between the client and us.
    var usb = try ctaphid.Usb.open(USB_PATH);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    var authenticator = fido.ctap.authenticator.Authenticator{
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .aaguid = "\x7f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // THe device is capable of accepting a PIN from the client
                .clientPin = true,
            },
            .pinUvAuthProtocols = &.{.V2},
            .transports = &.{.usb},
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
        },
        .attestation_type = .Self,
        .callbacks = .{
            .rand = callbacks.rand,
            .millis = callbacks.millis,
            .up = callbacks.up,
            .loadCurrentStoredPIN = callbacks.loadCurrentStoredPIN,
            .storeCurrentStoredPIN = callbacks.storeCurrentStoredPIN,
            .loadPINCodePointLength = callbacks.loadPINCodePointLength,
            .storePINCodePointLength = callbacks.storePINCodePointLength,
            .get_retries = callbacks.get_retries,
            .set_retries = callbacks.set_retries,
            .load_credential_by_id = callbacks.load_credential_by_id,
            .store_credential_by_id = callbacks.store_credential_by_id,
        },
        .token = .{
            .two = fido.ctap.pinuv.PinUvAuth{},
        },
        .allocator = gpa.allocator(),
    };

    if (authenticator.token.one) |*one| {
        one.initialize(authenticator.callbacks.rand);
    }
    if (authenticator.token.two) |*two| {
        two.initialize(authenticator.callbacks.rand);
    }

    while (true) {
        const msg = try usb.read();
        std.debug.print("{x}\n", .{std.fmt.fmtSliceHexUpper(msg)});

        var response = fido.ctap.transports.ctaphid.authenticator.handle(
            msg,
            &authenticator,
        );

        if (response) |*resp| {
            while (resp.next()) |packet| {
                try usb.write(packet);
            }
        }
    }
}