#include "wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

int main(void) {
  struct ws_hash want = SHA256;
  struct ws_hash got;
  assert(ws_nist_validate_hash(&SHA1, &got) == false);
  assert(strncmp(got.name, want.name, strlen(want.name)) == 0);
  assert(ws_nist_validate_hash(&SHA256, NULL) == true);
  assert(ws_nist_validate_hash(NULL, NULL) == -1);
}
