int *__errno_location(int *in_errnop, int *out_errnop);
// __errno_location_prologue function is for reference only, actual prologue
// code will need to be edited manually
void __errno_location_prologue(int *real_errno) {
#if defined(__GNUC__) && !defined(__clang__)
  void *sp = __builtin_stack_address(0);
#else
  register void *sp asm("sp");
  asm volatile("nop" : "=r"(sp) : "r"(sp) : "ra", "fp");
#endif
  __errno_location(real_errno, (int *)sp - (128 / sizeof(int)));
}

int *__errno_location(int *in_errnop, int *out_errnop) {
  int *errnop = in_errnop;
  const int errnov = *errnop;
  if (errnov < 35 || errnov > 133) {
    *out_errnop = errnov;
    return out_errnop;
  }
  if (errnov == 122) {
    *out_errnop = 1133;
    return out_errnop;
  }
#include "errno-lut.c"
  *out_errnop = errno_lut[errnov - 35];
  return out_errnop;
}
