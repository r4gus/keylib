const std = @import("std");
const fido = @import("fido");

const LoadError = fido.ctap.authenticator.Callbacks.LoadError;

var gpa: ?std.heap.GeneralPurposeAllocator(.{}) = null;
var credentials: ?std.ArrayList([]const u8) = null;
var id_map: ?std.ArrayList([]const u8) = null;

/// Fill the given buffer with (cryptographically secure) random bytes
pub fn rand(b: []u8) void {
    std.crypto.random.bytes(b);
}

/// Get the epoch time in ms
pub fn millis() u64 {
    return @intCast(u64, std.time.milliTimestamp());
}

pub fn up(user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) bool {
    _ = user;
    _ = rp;
    return true;
}

var pinHash: ?[32]u8 = null;

pub fn loadCurrentStoredPIN() LoadError![32]u8 {
    if (pinHash) |ph| {
        return ph;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storeCurrentStoredPIN(d: [32]u8) void {
    pinHash = d;
    std.debug.print("new pin hash: {x}\n", .{std.fmt.fmtSliceHexUpper(&pinHash.?)});
}

var l: ?u8 = null;

pub fn loadPINCodePointLength() LoadError!u8 {
    if (l) |len| {
        return len;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storePINCodePointLength(d: u8) void {
    l = d;
}

var retries: u8 = 8;

pub fn get_retries() LoadError!u8 {
    return retries;
}

pub fn set_retries(r: u8) void {
    retries = r;
}

pub fn load_credential_by_id(id: []const u8, a: std.mem.Allocator) LoadError![]const u8 {
    setup_db();

    std.debug.print("try load credential with id: {x}\n", .{
        std.fmt.fmtSliceHexUpper(id),
    });

    var i: usize = 0;
    while (i < credentials.?.items.len) : (i += 1) {
        if (std.mem.eql(u8, id_map.?.items[i], id)) {
            std.debug.print("found credential\n", .{});
            var mem = a.alloc(u8, credentials.?.items[i].len) catch {
                return LoadError.NotEnoughMemory;
            };
            @memcpy(mem, credentials.?.items[i]);
            return mem;
        }
    }

    std.debug.print("didn't find credential\n", .{});
    return LoadError.DoesNotExist;
}

pub fn store_credential_by_id(id: []const u8, d: []const u8) void {
    setup_db();

    std.debug.print("id: {x}, data: {x}\n", .{
        std.fmt.fmtSliceHexUpper(id),
        std.fmt.fmtSliceHexUpper(d),
    });

    var allocator = gpa.?.allocator();

    var mem = allocator.alloc(u8, d.len) catch unreachable;
    @memcpy(mem, d);

    var i: usize = 0;
    while (i < credentials.?.items.len) : (i += 1) {
        if (std.mem.eql(u8, id_map.?.items[i], id)) {
            allocator.free(credentials.?.items[i]);
            credentials.?.items[i] = mem;
            return;
        }
    }

    var idmem = allocator.alloc(u8, id.len) catch unreachable;
    @memcpy(idmem, id);

    id_map.?.append(idmem) catch unreachable;
    credentials.?.append(mem) catch unreachable;
}

// Helper
fn setup_db() void {
    if (credentials != null) return;

    gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.?.allocator();

    credentials = std.ArrayList([]const u8).init(allocator);
    id_map = std.ArrayList([]const u8).init(allocator);
}
