//! General properties of a given authenticator.

const dobj = @import("../dobj.zig");
const extension = @import("../extensions.zig");

/// versions: List of supported versions.
@"1": []const dobj.Versions,
/// extensions: List of supported extensions.
@"2": ?[]const extension.Extensions,
/// aaguid: The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
/// indicating the type of the authenticator. Authenticators with the
/// same capabilities and firmware, can share the same AAGUID.
@"3": [16]u8,
/// optoins: Supported options.
@"4": ?dobj.Options,
/// maxMsgSize: Maximum message size supported by the authenticator.
/// null = unlimited.
@"5": ?u64,
/// pinProtocols: List of supported PIN Protocol versions.
@"6": ?[]const u8, // TODO: add _a option to enforce array
/// A pin change is required Y/n
@"12": ?bool = false,