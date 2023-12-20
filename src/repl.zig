const std = @import("std");

const client = @import("client");
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const client_pin = client.cbor_commands.client_pin;
const cred_management = client.cbor_commands.cred_management;
const Info = client.cbor_commands.Info;

const stdin = std.io.getStdIn();
const stdout = std.io.getStdOut();

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

const State = struct {
    var transports: ?client.Transports = null;
    var device: ?*client.Transports.Transport = null;
    var n: ?usize = null;
};

pub fn main() !void {
    var input_buffer: [1024]u8 = undefined;

    defer {
        if (State.transports) |t| {
            t.deinit();
        }
        if (State.device) |dev| dev.close();
    }

    while (true) {
        try stdout.writer().writeByte('\n');
        if (State.n) |n| try stdout.writer().print("{d}", .{n});
        try stdout.writeAll("> ");
        const input = (try nextLine(stdin.reader(), &input_buffer)).?;
        const cmd = Command.from_raw(input);

        switch (cmd) {
            .Quit => break,
            .Help => try help(stdout.writer()),
            .ListDevices => try list_devices(stdout.writer()),
            .SelectDevice => try select_device(stdout.writer(), input),
            .GetInfo => try get_info(stdout.writer()),
            .None => try stdout.writeAll("unknown command"),
        }
    }
}

const Command = enum {
    /// Quit command `q`, `quit`, `e`, `exit`
    Quit,
    /// Show a help text `h`, `help`
    Help,
    /// List all available devices `l`, `list`
    ListDevices,
    /// Select a device
    SelectDevice,
    /// Get information about device
    GetInfo,
    /// Unknown kommand
    None,

    pub fn from_raw(in: []const u8) @This() {
        const l = in.len;

        if ((l > 0 and (in[0] == 'q' or in[0] == 'e')) or (l >= 4 and (std.mem.eql(u8, "quit", in[0..4]) or std.mem.eql(u8, "exit", in[0..4])))) {
            return .Quit;
        } else if ((l > 0 and in[0] == 'h') or (l >= 4 and std.mem.eql(u8, "help", in[0..4]))) {
            return .Help;
        } else if ((l > 0 and in[0] == 'l') or (l >= 4 and std.mem.eql(u8, "list", in[0..4]))) {
            return .ListDevices;
        } else if (l >= 6 and std.mem.eql(u8, "select", in[0..6])) {
            return .SelectDevice;
        } else if (l >= 7 and std.mem.eql(u8, "getInfo", in[0..7])) {
            return .GetInfo;
        } else {
            return .None;
        }
    }
};

fn help(writer: anytype) !void {
    try writer.writeAll(
        \\frepl - FIDO-Read-Eval-Print-Loop
        \\---------------------------------
        \\
        \\About: frepl is a interactive tool that lets you
        \\       communicate with a FIDO authenticator via
        \\       the command line.
        \\
        \\Commands:
        \\       q, quit: Quit the application
        \\       h, help: Print this help text
        \\
        \\       l, list: List all available authenticators
        \\       select <n>: Select the n'th available authenticator 
        \\       getInfo: Get information about a selected device
    );
}

fn list_devices(writer: anytype) !void {
    // Get all devices connect to the platform
    State.transports = try client.Transports.enumerate(allocator, .{});

    for (State.transports.?.devices, 0..) |*device, i| {
        if (i > 0) try writer.writeByte('\n');
        var str = try device.allocPrint(allocator);
        defer allocator.free(str);
        try writer.print("{d}) {s}", .{ i, str });
    }
}

fn select_device(writer: anytype, in: []const u8) !void {
    if (State.transports == null) {
        State.transports = try client.Transports.enumerate(allocator, .{});
    }

    if (State.transports.?.devices.len == 0) {
        try writer.writeAll("no device available");
    }

    var items = std.mem.split(u8, in, " ");
    _ = items.next();
    if (items.next()) |item| {
        const n = std.fmt.parseInt(usize, item, 0) catch {
            try writer.print("{s} is not a number", .{item});
            return;
        };

        if (n >= State.transports.?.devices.len) {
            try writer.print("please provide a number between {d} and {d}", .{ 0, State.transports.?.devices.len - 1 });
            return;
        }

        if (State.device) |dev| dev.close();

        State.device = &State.transports.?.devices[n];
        State.device.?.open() catch {
            try writer.print("unable to open device {d}", .{n});
            return;
        };
        State.n = n;
    } else {
        try writer.print("please provide a number between {d} and {d}", .{ 0, State.transports.?.devices.len - 1 });
    }
}

fn get_info(writer: anytype) !void {
    if (State.device == null) {
        try writer.writeAll("no device selected");
        return;
    }

    const infos = try (try authenticatorGetInfo(State.device.?)).@"await"(allocator);
    defer infos.deinit(allocator);
    const info = try infos.deserializeCbor(Info, allocator);
    defer info.deinit(allocator);
    try writer.print("{any}", .{info});
}

fn nextLine(reader: anytype, buffer: []u8) !?[]const u8 {
    var line = (try reader.readUntilDelimiterOrEof(
        buffer,
        '\n',
    )) orelse return null;
    // trim annoying windows-only carriage return character
    if (@import("builtin").os.tag == .windows) {
        return std.mem.trimRight(u8, line, "\r");
    } else {
        return line;
    }
}
