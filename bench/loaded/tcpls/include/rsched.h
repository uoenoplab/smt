#ifndef rsched_h
#define rsched_h
#include "picotypes.h"
#include "picotls.h"
#include "picotcpls.h"

int round_robin_con_scheduler(tcpls_t *tcpls, fd_set *rset, tcpls_buffer_t *decryptbuf, void *data);

#endif
