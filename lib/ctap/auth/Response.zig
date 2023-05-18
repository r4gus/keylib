pub const ResponseTag = enum { ok, err };

/// Authenticator response
pub const Response = union(ResponseTag) {
    /// Slice containing the response message
    ok: []const u8,
    /// A CTAP status code
    err: u8,
};
