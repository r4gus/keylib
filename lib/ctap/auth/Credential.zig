//! Representation of a credential created by an authenticator and bound
//! to a specific relying party.

const cbor = @import("zbor");

/// The id of the given credential
id: []const u8,

/// The id (base URL) the credential is bound to.
///
/// This might be null if the credential isn't stored
/// by the authenticator directly but derived from a
/// master secret.
rpId: ?[:0]const u8 = null,

/// The key in CBOR-COSE format
key: cbor.cose.Key,
