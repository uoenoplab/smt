.PATH: ${SRCTOP}/sys/netinet
.PATH: ${SRCTOP}/sys/netinet6

KMOD= smt
SRCS= smt_module.c smt_usrreq.c smt_structs.c smt_pcb.c smt_input.c \
	  smt_rpc.c smt_peer.c smt_output.c smt_ctx.c

SRCS+= opt_inet.h opt_inet6.h

.if defined(SMT_DEBUG)
OPT_FLAGS+= -DSMT_DEBUG
.endif

.if defined(SMT_TEST)
OPT_FLAGS+= -DSMT_TEST
SRCS+= smt_test.c
.endif

CFLAGS+= ${OPT_FLAGS}
# CFLAGS+= -DINVARIANTS -DINVARIANT_SUPPORT -DWITNESS

.include <bsd.kmod.mk>
