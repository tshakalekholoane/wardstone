/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ifc {
  pub k: u16,
}

/// Represents a choice of k = 1024 for an integer factorisation
/// cryptography primitive.
#[no_mangle]
pub static IFC_1024: Ifc = Ifc { k: 1024 };

/// Represents a choice of k = 2048 for an integer factorisation
/// cryptography primitive.
#[no_mangle]
pub static IFC_2048: Ifc = Ifc { k: 2048 };

/// Represents a choice of k = 3072 for an integer factorisation
/// cryptography primitive.
#[no_mangle]
pub static IFC_3072: Ifc = Ifc { k: 3027 };

/// Represents a choice of k = 7680 for an integer factorisation
/// cryptography primitive.
#[no_mangle]
pub static IFC_7680: Ifc = Ifc { k: 7680 };

/// Represents a choice of k = 15360 for an integer factorisation
/// cryptography primitive.
#[no_mangle]
pub static IFC_15360: Ifc = Ifc { k: 15360 };
