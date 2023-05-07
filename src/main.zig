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
