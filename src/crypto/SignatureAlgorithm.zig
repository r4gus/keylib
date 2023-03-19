//! Algorithm used for digital signatures

const cose = @import("zbor").cose;

/// COSE algorithm identifier
alg_id: cose.Algorithm,
