#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Symmetric {
  pub id: u16,
  pub security: u16,
}

#[no_mangle]
pub static AES128: Symmetric = Symmetric {
  id: 1,
  security: 128,
};

#[no_mangle]
pub static AES192: Symmetric = Symmetric {
  id: 2,
  security: 192,
};

#[no_mangle]
pub static AES256: Symmetric = Symmetric {
  id: 3,
  security: 256,
};

#[no_mangle]
pub static TDEA: Symmetric = Symmetric {
  id: 4,
  security: 112,
};
