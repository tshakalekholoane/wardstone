#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Symmetric {
  pub id: u16,
  pub security: u16,
}

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES128: Symmetric = Symmetric {
  id: 1,
  security: 128,
};

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES192: Symmetric = Symmetric {
  id: 2,
  security: 192,
};

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES256: Symmetric = Symmetric {
  id: 3,
  security: 256,
};

/// The two-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA2: Symmetric = Symmetric {
  id: 4,
  security: 95,
};

/// The three-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA3: Symmetric = Symmetric {
  id: 5,
  security: 112,
};
