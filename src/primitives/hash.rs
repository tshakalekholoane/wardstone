#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Hash(pub u16);

macro_rules! hash {
  ($name:ident, $len:expr) => {
    #[no_mangle]
    pub static $name: Hash = Hash($len);
  };
}

hash!(BLAKE2b_256, 256);
hash!(BLAKE2b_384, 384);
hash!(BLAKE2b_512, 512);
hash!(BLAKE2s_256, 256);
hash!(MD4, 128);
hash!(MD5, 128);
hash!(RIPEMD160, 160);
hash!(SHA1, 160);
hash!(SHA256, 256);
hash!(SHA3_224, 224);
hash!(SHA3_256, 256);
hash!(SHA3_384, 384);
hash!(SHA3_512, 512);
hash!(SHA3_512_224, 224);
hash!(SHA3_512_256, 256);
hash!(SHA512, 512);
