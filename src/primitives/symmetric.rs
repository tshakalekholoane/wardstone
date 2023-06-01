#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Symmetric(pub u16);

#[no_mangle]
pub static AES128: Symmetric = Symmetric(128);
#[no_mangle]
pub static AES192: Symmetric = Symmetric(192);
#[no_mangle]
pub static AES256: Symmetric = Symmetric(256);
#[no_mangle]
pub static TDEA: Symmetric = Symmetric(112);
