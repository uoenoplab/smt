#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IPPROTO_SDTP	146

int
main(void)
{
	int error;
	int fd;

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_SDTP);
	if (fd >= 0) {
		fprintf(stderr, "IPv6 SDTP socket unexpectedly succeeded\n");
		close(fd);
		return (1);
	}
	error = errno;
	if (error != EPROTONOSUPPORT) {
		fprintf(stderr, "socket failed with %s, expected %s\n",
		    strerror(error), strerror(EPROTONOSUPPORT));
		return (1);
	}

	return (0);
}
