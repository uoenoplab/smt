#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../homa.h"
#include "../smt_uapi.h"

// gcc -Wall smt_setkey.c ../smt_uapi.c -o smt_setkey
int main(void)
{
    int status = 0;
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
    if (sockfd < 0) {
        printf("Couldn't open Homa socket: %s\n", strerror(errno));
        goto socket;
    }

    char *region = (char *) mmap(NULL, 64*HOMA_BPAGE_SIZE,
            PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (region == MAP_FAILED) {
        printf("Couldn't mmap buffer region: %s\n", strerror(errno));
        goto mmap;
    }

    struct homa_rcvbuf_args arg;
    arg.start = (uintptr_t)region;
    arg.length = 64*HOMA_BPAGE_SIZE;
    status = setsockopt(sockfd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &arg,
            sizeof(arg));
    if (status < 0) {
        printf("Error in setsockopt(SO_HOMA_RCVBUF): %s\n",
                strerror(errno));
        goto rbuf;
    }

    int ret = smt_aes_gcm_128_setsockopt_hardcodekey_helper(sockfd, 0, 0, 0, 0, 0);
    if (ret < 0) {
        printf("Couldn't set SMT options on socket: %d %s\n", ret,
               strerror(errno));
        goto setkey;
    }

    printf("SMT options successfully set on socket.\n");
    return 0;

setkey:
rbuf:
    munmap(region, 64*HOMA_BPAGE_SIZE);
mmap:
    close(sockfd);
socket:
    return ESOCKTNOSUPPORT;
}
