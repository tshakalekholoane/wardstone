#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Symmetric(pub u16);

macro_rules! symmetric {
  ($name:ident, $len:expr) => {
    #[no_mangle]
    pub static $name: Symmetric = Symmetric($len);
  };
}

symmetric!(AES128, 128);
symmetric!(AES192, 192);
symmetric!(AES256, 256);
symmetric!(TDEA, 112);
