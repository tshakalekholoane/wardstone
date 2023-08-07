#include "wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

int main(void) {
  struct ws_hash got = {0};
  const struct ws_hash* want = WS_SHA224;
  struct ws_context ctx = ws_context_default();
  assert(ws_nist_validate_hash(&ctx, WS_SHA1, &got) == false && "SHA1 should fail");
  assert(got.id == want->id && "unexpected hash function recommendation");
  assert(ws_nist_validate_hash(&ctx, WS_SHA256, NULL) == true && "SHA256 should pass");
  assert(ws_nist_validate_hash(NULL, NULL, NULL) == -1 && "null pointer should err");
}
