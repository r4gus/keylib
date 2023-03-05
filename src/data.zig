pub const Authenticator = @import("data/Authenticator.zig");
pub const AttestationType = @import("data/attestation.zig").AttestationType;
pub const Options = @import("data/Options.zig");
pub const Settings = @import("data/Settings.zig");
pub const Versions = @import("data/versions.zig").Versions;

test "data tests" {
    _ = Authenticator;
    _ = AttestationType;
    _ = Options;
    _ = Settings;
    _ = Versions;
}
