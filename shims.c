extern int stat64(const char *path, void *buf);
extern int lstat64(const char *path, void *buf);
extern int fstat64(int fildes, void *buf);
extern int fstatat64(int dirfd, const char *pathname, void *buf, int flags);
extern int mknod(const char *__path, unsigned int __mode, unsigned int __dev);
extern int mknodat(int fd, const char *path, unsigned int mode,
                   unsigned int dev);

int __xstat64(int ver, const char *path, void *buf) {
  return stat64(path, buf);
}
int __lxstat64(int ver, const char *path, void *buf) {
  return lstat64(path, buf);
}
int __fxstat64(int ver, int fildes, void *buf) { return fstat64(fildes, buf); }
int __fxstatat64(int ver, int __fildes, const char *__filename,
                 void *__stat_buf, int __flag) {
  return fstatat64(__fildes, __filename, __stat_buf, __flag);
}
int __xstat(int ver, const char *path, void *buf) { return stat64(path, buf); }
int __lxstat(int ver, const char *path, void *buf) {
  return lstat64(path, buf);
}
int __fxstat(int ver, int fildes, void *buf) { return fstat64(fildes, buf); }

int __xmknod(int __ver, const char *__path, unsigned int __mode,
             unsigned int *__dev) {
  return mknod(__path, __mode, *__dev);
}
int __xmknodat(int __ver, int __fd, const char *__path, unsigned int __mode,
               unsigned int *__dev) {
  return mknodat(__fd, __path, __mode, *__dev);
}

extern int *__errno_location(void);

// void* __tls_get_addr_dummy() {
//   // dummy implementation, used to avoid using __tls_get_addr() when the to-be-patched binary doesn't use thread-local storage
//   // module = 1, offset = 0
//   return __builtin_thread_pointer();
// }

// TODO: patching in a thread-local variable is very difficult, as this will need adding a new TLS segment
static /*_Thread_local*/ int errnop = 0;

#ifndef __LAPD_USE_ERRNO_SWITCH
void __errno_location_wrapper(int *out_errnop) {
  int *errnop = __errno_location();
  const int errnov = *errnop;
  if (errnov < 35 || errnov > 133) {
    *out_errnop = errnov;
    return;
  }
  if (errnov == 122) {
    *out_errnop = 1133;
    return;
  }
#include "errno-lut.c"
  *out_errnop = errno_lut[errnov - 35];
}
#else

#include "errno-switch.inc.c"
int *__errno_location_wrapper(void) {
  errnop = errnov(*__errno_location());
  return &errnop;
}
#endif