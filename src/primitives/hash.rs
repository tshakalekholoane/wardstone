/// cbindgen:field-names=[digest_len]
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Hash(pub u16);

#[no_mangle]
pub static BLAKE2b_256: Hash = Hash(256);
#[no_mangle]
pub static BLAKE2b_384: Hash = Hash(384);
#[no_mangle]
pub static BLAKE2b_512: Hash = Hash(512);
#[no_mangle]
pub static BLAKE2s_256: Hash = Hash(256);
#[no_mangle]
pub static MD4: Hash = Hash(128);
#[no_mangle]
pub static MD5: Hash = Hash(128);
#[no_mangle]
pub static RIPEMD160: Hash = Hash(160);
#[no_mangle]
pub static SHA1: Hash = Hash(160);
#[no_mangle]
pub static SHA256: Hash = Hash(256);
#[no_mangle]
pub static SHA3_224: Hash = Hash(224);
#[no_mangle]
pub static SHA3_256: Hash = Hash(256);
#[no_mangle]
pub static SHA3_384: Hash = Hash(384);
#[no_mangle]
pub static SHA3_512: Hash = Hash(512);
#[no_mangle]
pub static SHA3_512_224: Hash = Hash(224);
#[no_mangle]
pub static SHA3_512_256: Hash = Hash(256);
#[no_mangle]
pub static SHA512: Hash = Hash(512);
