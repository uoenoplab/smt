TESTSDIR= ${TESTSBASE}/sys/modules/sdtp
BINDIR= ${TESTSDIR}

ATF_TESTS_SH+= sdtp_integration

PROGS+= sdtp_test_send
PROGS+= sdtp_test_recv
PROGS+= sdtp_test_ipv6
PROGS+= sdtp_test_close

LIBADD.sdtp_test_send= pthread

CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/sys/modules/sdtp

TEST_METADATA.sdtp_integration+= execenv="jail"
TEST_METADATA.sdtp_integration+= execenv_jail_params="vnet"
TEST_METADATA.sdtp_integration+= required_programs="ifconfig jail jexec kldload kldunload"
TEST_METADATA.sdtp_integration+= is_exclusive="true"

.include <bsd.test.mk>
