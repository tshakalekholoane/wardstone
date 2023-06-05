#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Symmetric {
  pub name: &'static str,
  pub security: u16,
}

#[no_mangle]
pub static AES128: Symmetric = Symmetric {
  name: "AES128",
  security: 128,
};

#[no_mangle]
pub static AES192: Symmetric = Symmetric {
  name: "AES192",
  security: 192,
};

#[no_mangle]
pub static AES256: Symmetric = Symmetric {
  name: "AES256",
  security: 256,
};

#[no_mangle]
pub static TDEA: Symmetric = Symmetric {
  name: "TDEA",
  security: 112,
};
