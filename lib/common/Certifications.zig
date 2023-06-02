//! An authenticator’s supported certifications MAY be returned in the certifications
//! member of an authenticatorGetInfo response.

/// The [FIPS140-2] Cryptographic-Module-Validation-Program overall certification level.
/// This is a integer from 1 to 4.
@"FIPS-CMVP-2": ?u8 = null,

/// The [FIPS140-3] [CMVP] or ISO/IEC 19790:2012(E) and ISO/IEC 24759:2017(E) overall
/// certification level. This is a integer from 1 to 4.
@"FIPS-CMVP-3": ?u8 = null,

/// The [FIPS140-2] Cryptographic-Module-Validation-Program physical certification level.
/// This is a integer from 1 to 4.
@"FIPS-CMVP-2-PHY": ?u8 = null,

/// The [FIPS140-3] [CMVP] or ISO/IEC 19790:2012(E) and ISO/IEC 24759:2017(E) physical
/// certification level. This is a integer from 1 to 4.
@"FIPS-CMVP-3-PHY": ?u8 = null,

/// Common Criteria Evaluation Assurance Level [CC1V3-1R5]. This is a integer
/// from 1 to 7. The intermediate-plus levels are not represented.
@"CC-EAL": ?u8 = null,

/// FIDO Alliance certification level. This is an integer from 1 to 6. The
/// numbered levels are mapped to the odd numbers, with the plus levels
/// mapped to the even numbers e.g., level 3+ is mapped to 6.
FIDO: ?u8 = null,
