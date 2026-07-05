TESTSDIR= ${TESTSBASE}/sys/modules/smt
BINDIR= ${TESTSDIR}

ATF_TESTS_SH+= smt_integration

PROGS+= smt_test_send
PROGS+= smt_test_recv
PROGS+= smt_test_ipv6
PROGS+= smt_test_close

LIBADD.smt_test_send= pthread

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${.CURDIR}/..

TEST_METADATA.smt_integration+= execenv="jail"
TEST_METADATA.smt_integration+= execenv_jail_params="vnet"
TEST_METADATA.smt_integration+= required_programs="ifconfig jail jexec kldload kldunload"
TEST_METADATA.smt_integration+= is_exclusive="true"

.include <bsd.test.mk>
