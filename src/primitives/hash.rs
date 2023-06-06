#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Hash {
  pub id: u16,
  pub digest_len: u16,
}

#[no_mangle]
pub static BLAKE2b_256: Hash = Hash {
  id: 1,
  digest_len: 256,
};

#[no_mangle]
pub static BLAKE2b_384: Hash = Hash {
  id: 2,
  digest_len: 384,
};

#[no_mangle]
pub static BLAKE2b_512: Hash = Hash {
  id: 3,
  digest_len: 512,
};

#[no_mangle]
pub static BLAKE2s_256: Hash = Hash {
  id: 4,
  digest_len: 256,
};

#[no_mangle]
pub static MD4: Hash = Hash {
  id: 5,
  digest_len: 128,
};

#[no_mangle]
pub static MD5: Hash = Hash {
  id: 6,
  digest_len: 128,
};

#[no_mangle]
pub static RIPEMD160: Hash = Hash {
  id: 7,
  digest_len: 160,
};

#[no_mangle]
pub static SHA1: Hash = Hash {
  id: 8,
  digest_len: 160,
};

pub static SHA224: Hash = Hash {
  id: 9,
  digest_len: 224,
};

#[no_mangle]
pub static SHA256: Hash = Hash {
  id: 10,
  digest_len: 256,
};

#[no_mangle]
pub static SHA384: Hash = Hash {
  id: 11,
  digest_len: 384,
};

#[no_mangle]
pub static SHA3_224: Hash = Hash {
  id: 12,
  digest_len: 224,
};

#[no_mangle]
pub static SHA3_256: Hash = Hash {
  id: 13,
  digest_len: 256,
};

#[no_mangle]
pub static SHA3_384: Hash = Hash {
  id: 14,
  digest_len: 384,
};

#[no_mangle]
pub static SHA3_512: Hash = Hash {
  id: 15,
  digest_len: 512,
};

#[no_mangle]
pub static SHA3_512_224: Hash = Hash {
  id: 16,
  digest_len: 224,
};

#[no_mangle]
pub static SHA3_512_256: Hash = Hash {
  id: 17,
  digest_len: 256,
};

#[no_mangle]
pub static SHA512: Hash = Hash {
  id: 18,
  digest_len: 512,
};

#[no_mangle]
pub static SHA512_224: Hash = Hash {
  id: 19,
  digest_len: 224,
};

#[no_mangle]
pub static SHA512_256: Hash = Hash {
  id: 20,
  digest_len: 256,
};
