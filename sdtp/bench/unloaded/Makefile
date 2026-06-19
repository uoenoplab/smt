.PATH: ${.CURDIR}/../loaded

PROGS=	simple_client simple_server sdtp_simple_client sdtp_simple_server
MAN=

SRCS.simple_client=	sdtp_simple_client.c sdtp_simple.c sdtp_bench.c
SRCS.simple_server=	sdtp_simple_server.c sdtp_simple.c sdtp_bench.c
SRCS.sdtp_simple_client=	sdtp_simple_client.c sdtp_simple.c sdtp_bench.c
SRCS.sdtp_simple_server=	sdtp_simple_server.c sdtp_simple.c sdtp_bench.c

LIBADD.simple_client=	pthread m
LIBADD.simple_server=	pthread m
LIBADD.sdtp_simple_client=	pthread m
LIBADD.sdtp_simple_server=	pthread m

CFLAGS+=	-I${.CURDIR}/../loaded

.include <bsd.progs.mk>
