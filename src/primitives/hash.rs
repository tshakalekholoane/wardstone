#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Hash {
  pub name: &'static str,
  pub digest_len: u16,
}

#[no_mangle]
pub static BLAKE2b_256: Hash = Hash {
  name: "BLAKE2b_256",
  digest_len: 256,
};

#[no_mangle]
pub static BLAKE2b_384: Hash = Hash {
  name: "BLAKE2b_384",
  digest_len: 384,
};

#[no_mangle]
pub static BLAKE2b_512: Hash = Hash {
  name: "BLAKE2b_512",
  digest_len: 512,
};

#[no_mangle]
pub static BLAKE2s_256: Hash = Hash {
  name: "BLAKE2s_256",
  digest_len: 256,
};

#[no_mangle]
pub static BLAKE3_256: Hash = Hash {
  name: "BLAKE3_256",
  digest_len: 256,
};

#[no_mangle]
pub static MD4: Hash = Hash {
  name: "MD4",
  digest_len: 128,
};

#[no_mangle]
pub static MD5: Hash = Hash {
  name: "MD5",
  digest_len: 128,
};

#[no_mangle]
pub static RIPEMD160: Hash = Hash {
  name: "RIPEMD160",
  digest_len: 160,
};

#[no_mangle]
pub static SHA1: Hash = Hash {
  name: "SHA1",
  digest_len: 160,
};

#[no_mangle]
pub static SHA256: Hash = Hash {
  name: "SHA256",
  digest_len: 256,
};

#[no_mangle]
pub static SHA3_224: Hash = Hash {
  name: "SHA3_224",
  digest_len: 224,
};

#[no_mangle]
pub static SHA3_256: Hash = Hash {
  name: "SHA3_256",
  digest_len: 256,
};

#[no_mangle]
pub static SHA3_384: Hash = Hash {
  name: "SHA3_384",
  digest_len: 384,
};

#[no_mangle]
pub static SHA3_512: Hash = Hash {
  name: "SHA3_512",
  digest_len: 512,
};

#[no_mangle]
pub static SHA3_512_224: Hash = Hash {
  name: "SHA3_512_224",
  digest_len: 224,
};

#[no_mangle]
pub static SHA3_512_256: Hash = Hash {
  name: "SHA3_512_256",
  digest_len: 256,
};

#[no_mangle]
pub static SHA512: Hash = Hash {
  name: "SHA512",
  digest_len: 512,
};
