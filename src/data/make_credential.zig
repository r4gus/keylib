pub const MakeCredentialParam = @import("make_credential/MakeCredentialParam.zig");
pub const attestation = @import("make_credential/attestation.zig");

test "make credential tests" {
    _ = MakeCredentialParam;
    _ = attestation;
}
