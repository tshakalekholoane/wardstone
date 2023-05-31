#include "include/wardstone.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

uint16_t get_current_year() {
  auto unix_time_now = time(nullptr);
  auto localtime_now = localtime(&unix_time_now);
  return localtime_now->tm_year + 1900;
}

int main(void) {
  auto current_year = get_current_year();

  assert(lenstra_validate_hash(&SHA1, current_year) == false);
  assert(lenstra_validate_hash(&SHA256, current_year) == true);
  assert(lenstra_validate_hash(nullptr, current_year) == -1);
}
