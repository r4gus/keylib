const std = @import("std");

const clap = @import("clap");
const io = std.io;
const debug = std.debug;

const fido = @import("fido");
const usb = fido.client.transports.usb;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-e, --enumerate        Enumerate all security tokens
        \\-i, --info <str>       Get information about the specified authenticator
        \\-r, --reset <str>      Reset the given authenticator
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        // Report useful error and exit
        diag.report(io.getStdErr().writer(), err) catch {};
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    };
    defer res.deinit();

    if (res.args.help != 0) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    } else if (res.args.enumerate != 0) {
        var authenticators = try usb.enumerate(allocator);
        defer {
            for (authenticators) |*auth| {
                auth.deinit();
            }
        }

        for (authenticators) |*auth| {
            std.debug.print("{s}\n", .{
                if (auth.transport.info) |info| info else auth.transport.path,
            });
        }
    } else if (res.args.info) |path| {
        var auth = try fido.client.transports.usb.open_with_path(path, allocator);
        defer auth.deinit();

        const info = try fido.client.commands.cbor.authenticatorGetInfo(&auth);
        defer info.deinit(auth.transport.allocator);

        var info_str = std.ArrayList(u8).init(allocator);
        defer info_str.deinit();
        try info.to_string(info_str.writer());

        std.debug.print("{s}\n", .{info_str.items});
    } else if (res.args.reset) |path| {
        var auth = try fido.client.transports.usb.open_with_path(path, allocator);
        defer auth.deinit();

        fido.client.commands.cbor.authenticatorReset(&auth) catch {
            std.debug.print("can't reset device\n", .{});
        };
    }
}
