.PATH: ${.CURDIR}/../loaded

PROGS=	simple_client simple_server smt_simple_client smt_simple_server
MAN=

SRCS.simple_client=	smt_simple_client.c smt_simple.c smt_bench.c
SRCS.simple_server=	smt_simple_server.c smt_simple.c smt_bench.c
SRCS.smt_simple_client=	smt_simple_client.c smt_simple.c smt_bench.c
SRCS.smt_simple_server=	smt_simple_server.c smt_simple.c smt_bench.c

LIBADD.simple_client=	pthread m
LIBADD.simple_server=	pthread m
LIBADD.smt_simple_client=	pthread m
LIBADD.smt_simple_server=	pthread m

CFLAGS+=	-I${.CURDIR}/../loaded

.include <bsd.progs.mk>
