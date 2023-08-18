# Wardstone FFI

The `wardstone_ffi` library contains a subset of the [`wardstone_core`](../core/) functionality. It's main purpose is to expose a C API that can be used to interface with other programming languages that support it.

It uses [`cbindgen`](https://github.com/mozilla/cbindgen) to generate C/C++ headers and dynamic and static libraries that can be found in the `target` directory after building the crate.

The following is a C example that illustrates how this API can be called from other programming languages:

```c
#include "wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

int main(void) {
  struct ws_hash got;
  memset(&got, 0, sizeof(struct ws_hash));
  struct ws_hash want = WS_SHA224;
  struct ws_context ctx = ws_context_default();
  assert(ws_nist_validate_hash(ctx, WS_SHA1, &got) == false && "SHA1 should fail");
  assert(got.id == want.id && "unexpected hash function recommendation");
  assert(ws_nist_validate_hash(ctx, WS_SHA256, NULL) == true && "SHA256 should pass");
}
```

See the [`examples`](/examples/ffi/) directory for more details about how to compile and run this code.
