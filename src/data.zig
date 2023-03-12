pub const AttestationType = @import("data/attestation.zig").AttestationType;
pub const Options = @import("data/Options.zig");
pub const Settings = @import("data/Settings.zig");
pub const Versions = @import("data/versions.zig").Versions;
pub const State = @import("data/State.zig");
pub const User = @import("data/User.zig");
pub const RelyingParty = @import("data/RelyingParty.zig");
pub const ErrorCodes = @import("data/error.zig").ErrorCodes;
pub const Errors = @import("data/error.zig").Errors;
pub const StatusCodes = @import("data/status_codes.zig").StatusCodes;
pub const client_pin = @import("data/client_pin.zig");
pub const data = @import("data/data.zig");
pub const PublicData = data.PublicData;
pub const PrivateData = data.PrivateData;

test "data tests" {
    _ = AttestationType;
    _ = Options;
    _ = Settings;
    _ = Versions;
    _ = State;
    _ = client_pin;
    _ = data;
}
