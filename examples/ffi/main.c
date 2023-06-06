#include "wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

int main(void) {
  struct ws_hash got;
  struct ws_hash want = SHA256;
  assert(ws_nist_validate_hash(&SHA1, &got) == false && "SHA1 should fail");
  assert(got.id == want.id && "unexpected hash function recommendation");
  assert(ws_nist_validate_hash(&SHA256, NULL) == true && "SHA256 should pass");
  assert(ws_nist_validate_hash(NULL, NULL) == -1 && "null pointer should err");
}
