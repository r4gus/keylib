pub const Extensions = enum {
    unknown,
    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .unknown => "unknown",
        };
    }
};
