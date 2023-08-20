const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ProfilingAllocator = struct {
    parent_allocator: Allocator,
    map: std.AutoHashMap(usize, usize),
    current_size: usize = 0,
    max_size: usize = 0,

    const Self = @This();

    pub fn init(parent_allocator: Allocator, second_allocator: Allocator) Self {
        return .{
            .parent_allocator = parent_allocator,
            .map = std.AutoHashMap(usize, usize).init(second_allocator),
        };
    }

    pub fn allocator(self: *Self) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    pub fn printStats(self: *Self) void {
        std.log.info("current_size={d}", .{self.current_size});
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        log2_ptr_align: u8,
        ra: usize,
    ) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const result = self.parent_allocator.rawAlloc(len, log2_ptr_align, ra);
        if (result != null) {
            const addr = @intFromPtr(result);
            self.map.put(addr, len) catch unreachable;
            self.current_size += len;

            if (self.max_size < self.current_size) {
                self.max_size = self.current_size;
            }
        } else {
            std.log.err(
                "alloc - failure: OutOfMemory - len: {}, ptr_align: {}",
                .{ len, log2_ptr_align },
            );
        }
        return result;
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_len: usize,
        ra: usize,
    ) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.parent_allocator.rawResize(buf, log2_buf_align, new_len, ra)) {
            const addr = @intFromPtr(&buf[0]);
            const len = self.map.get(addr).?;
            self.map.put(addr, new_len) catch unreachable;

            self.current_size -= len;
            self.current_size += new_len;

            if (self.max_size < self.current_size) {
                self.max_size = self.current_size;
            }

            return true;
        }

        std.debug.assert(new_len > buf.len);
        std.log.err(
            "expand - failure - {} to {}, buf_align: {}",
            .{ buf.len, new_len, log2_buf_align },
        );
        return false;
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        ra: usize,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.parent_allocator.rawFree(buf, log2_buf_align, ra);
        const addr = @intFromPtr(&buf[0]);
        const len = self.map.get(addr).?;
        self.current_size -= len;
        _ = self.map.remove(addr);
    }
};
