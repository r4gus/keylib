const std = @import("std");

const fido = @import("fido");
const usb = fido.client.transports.usb;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    //usb.init();

    var authenticators = try usb.enumerate(allocator);
    defer {
        for (authenticators) |*auth| {
            auth.deinit();
        }
    }

    for (authenticators) |*auth| {
        //std.debug.print("{s}: vendor={x}, product={x} ({s} {s})\n", .{
        //    auth.transport.usb.path,
        //    auth.transport.usb.vendor_id,
        //    auth.transport.usb.product_id,
        //    auth.transport.usb.manufacturer_string,
        //    auth.transport.usb.product_string,
        //});

        std.debug.print("{s}\n", .{
            if (auth.transport.info) |info| info else auth.transport.path,
        });

        auth.open() catch {
            std.debug.print("can't open device\n", .{});
        };

        const info = try fido.client.commands.cbor.authenticatorGetInfo(auth);
        defer info.deinit(auth.transport.allocator);

        var info_str = std.ArrayList(u8).init(allocator);
        defer info_str.deinit();
        try info.to_string(info_str.writer());

        std.debug.print("{s}\n", .{info_str.items});
    }

    //for (authenticators) |*auth| {
    //    std.debug.print("{s}: vendor={x}, product={x} ({s} {s})\n", .{
    //        auth.transport.usb.path,
    //        auth.transport.usb.vendor_id,
    //        auth.transport.usb.product_id,
    //        auth.transport.usb.manufacturer_string,
    //        auth.transport.usb.product_string,
    //    });
    //    auth.open() catch {
    //        std.debug.print("can't open device\n", .{});
    //    };
    //    const r = fido.client.commands.ctaphid.ctaphid_init(auth, 0xffffffff, allocator) catch {
    //        std.debug.print("couldn't send init request\n", .{});
    //        auth.close();
    //        return;
    //    };
    //    std.debug.print("cid: {x}\n", .{r.cid});
    //    auth.close();
    //}
}
