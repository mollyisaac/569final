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

extern char *buf_to_file(const uint8_t *buf, size_t size) {
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


int main(){

//     std::string path(buf_to_file((uint8_t*)"12345", 1));


    TemplateISO19794_2_2005<uint32_t, Fingerprint> t1(1);
//    if(!t1.load("crash-emptyfile")){
 if(!t1.load("crash-be5d974ab3354951848745ae861479c471549135")){
      //  std::cout <<  "fail to load crashing input" << std::endl;
      //  return 0;
    }

    TemplateISO19794_2_2005<uint32_t, Fingerprint> t2(2);
    if (!t2.load("/home/fuzzusers/openafis/data/valid/fvc2002/DB1_B/101_2.iso")) {
    }

    MatchSimilarity match;
    uint8_t s {};
    match.compute(s, t1.fingerprints()[0], t2.fingerprints()[0]);
    std::cout << "matching completes" << std::endl;
    return 0;

}
