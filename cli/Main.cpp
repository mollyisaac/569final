#include "OpenAFIS.h"
#include <iostream>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace OpenAFIS;

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
extern "C" int ignore_stdout(void) {
  int fd = open("/dev/null", O_WRONLY);
  if (fd == -1) {
    warn("open(\"/dev/null\") failed");
    return -1;
  }

  int ret = 0;
  if (dup2(fd, STDOUT_FILENO) == -1) {
    warn("failed to redirect stdout to /dev/null\n");
    ret = -1;
  }

  if (close(fd) == -1) {
    warn("close");
    ret = -1;
  }

  return ret;
}

extern "C" int delete_file(const char *pathname) {
  int ret = unlink(pathname);
  if (ret == -1) {
    warn("failed to delete \"%s\"", pathname);
  }

  free((void *)pathname);

  return ret;
}

extern "C" char *buf_to_file(const uint8_t *buf, size_t size) {
  static char *pathname = strdup("/dev/shm/fuzz-XXXXXX");
  if (pathname == nullptr) {
    return nullptr;
  }

  int fd = mkstemp(pathname);
  if (fd == -1) {
    warn("mkstemp(\"%s\")", pathname);
    free(pathname);
    return nullptr;
  }

  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      if (nbytes == -1 && errno == EINTR) {
        continue;
      }
      warn("write");
      goto err;
    }
    pos += nbytes;
  }

  if (close(fd) == -1) {
    warn("close");
    goto err;
  }

  return pathname;

err:
  delete_file(pathname);
  return nullptr;
}

//extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
int main()
{
   // std::string path(buf_to_file(Data, Size));

    TemplateISO19794_2_2005<uint32_t, Fingerprint> t1(1);
    std::string p1("/home/fuzzusers/openafis/data/valid/fvc2002/DB1_B/101_2.iso");
    std::string p2("/home/fuzzusers/openafis/data/valid/fvc2002/DB1_B/101_2.iso");

    if (!t1.load(p1)) {
        std::exit(0);
    }

    TemplateISO19794_2_2005<uint32_t, Fingerprint> t2(2);
    if (!t2.load(p2)) {
        // Load error;
    }

    MatchSimilarity match;
    uint8_t s {};
    match.compute(s, t1.fingerprints()[0], t2.fingerprints()[0]);
    std::cout << "similarity = " << s << std::endl;

    return 0;
}


