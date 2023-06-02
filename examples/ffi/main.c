#include "wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

int get_current_year() {
  time_t now = time(NULL);
  struct tm* local_time = localtime(&now);
  return local_time->tm_year + 1900;
}

int main(void) {
  uint16_t current_year = get_current_year();
  assert(lenstra_validate_hash(&SHA1, current_year) == false);
  assert(lenstra_validate_hash(&SHA256, current_year) == true);
  assert(lenstra_validate_hash(NULL, current_year) == -1);
}
