.PATH: ${SRCTOP}/sys/netinet
.PATH: ${SRCTOP}/sys/netinet6

KMOD= sdtp
SRCS= sdtp_module.c sdtp_usrreq.c sdtp_structs.c sdtp_pcb.c sdtp_input.c \
	  sdtp_rpc.c sdtp_peer.c sdtp_output.c sdtp_ctx.c

SRCS+= opt_inet.h opt_inet6.h

.if defined(SDTP_DEBUG)
OPT_FLAGS+= -DSDTP_DEBUG
.endif

.if defined(SDTP_TEST)
OPT_FLAGS+= -DSDTP_TEST
SRCS+= sdtp_test.c
.endif

CFLAGS+= ${OPT_FLAGS}
# CFLAGS+= -DINVARIANTS -DINVARIANT_SUPPORT -DWITNESS

.include <bsd.kmod.mk>
