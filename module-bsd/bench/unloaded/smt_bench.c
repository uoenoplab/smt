/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ktls.h>
#include <sys/socket.h>

#ifdef __FreeBSD__
#include <sys/cpuset.h>
#endif

#include <netinet/in.h>

#include <arpa/inet.h>
#include <crypto/cryptodev.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../tests/smt_test_tls.h"
#include "smt_bench.h"

volatile sig_atomic_t smt_bench_stop;

static void
smt_bench_signal_handler(int signo)
{
	(void)signo;
	smt_bench_stop = 1;
}

int
smt_bench_parse_int(const char *text, int minimum, int maximum, int *value)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno != 0 || *text == '\0' || *end != '\0' || parsed < minimum ||
	    parsed > maximum)
		return (-1);
	*value = (int)parsed;
	return (0);
}

int
smt_bench_parse_u16(const char *text, uint16_t *value)
{
	int parsed;

	if (smt_bench_parse_int(text, 1, UINT16_MAX, &parsed) != 0)
		return (-1);
	*value = (uint16_t)parsed;
	return (0);
}

int
smt_bench_parse_ports(const char *text, uint16_t *base_port, int *num_ports)
{
	char buffer[32], *separator;
	uint16_t first, last;
	size_t length;

	length = strlen(text);
	if (length == 0 || length >= sizeof(buffer))
		return (-1);
	memcpy(buffer, text, length + 1);
	separator = strchr(buffer, '-');
	if (separator == NULL) {
		if (smt_bench_parse_u16(buffer, &first) != 0)
			return (-1);
		last = first;
	} else {
		*separator = '\0';
		if (smt_bench_parse_u16(buffer, &first) != 0 ||
		    smt_bench_parse_u16(separator + 1, &last) != 0 ||
		    last < first)
			return (-1);
	}
	*base_port = first;
	*num_ports = (int)last - (int)first + 1;
	return (0);
}

int
smt_bench_parse_sizes(char *text, uint32_t *request_size,
    uint32_t *response_size)
{
	char *separator;
	int request, response;

	separator = strchr(text, ',');
	if (separator == NULL) {
		if (smt_bench_parse_int(text, 1, SMT_BENCH_MAX_MESSAGE_LENGTH,
			&request) != 0)
			return (-1);
		response = request;
	} else {
		*separator = '\0';
		if (smt_bench_parse_int(text, 1, SMT_BENCH_MAX_MESSAGE_LENGTH,
			&request) != 0 ||
		    smt_bench_parse_int(separator + 1, 1,
			SMT_BENCH_MAX_MESSAGE_LENGTH, &response) != 0) {
			*separator = ',';
			return (-1);
		}
		*separator = ',';
	}

	*request_size = (uint32_t)request;
	*response_size = (uint32_t)response;
	return (0);
}

int
smt_bench_parse_protocol(const char *text, enum smt_bench_protocol *protocol)
{
	if (strcmp(text, "homa") == 0)
		*protocol = SMT_BENCH_PROTO_HOMA;
	else if (strcmp(text, "smt") == 0)
		*protocol = SMT_BENCH_PROTO_SMT;
	else
		return (-1);
	return (0);
}

const char *
smt_bench_protocol_name(enum smt_bench_protocol protocol)
{
	switch (protocol) {
	case SMT_BENCH_PROTO_HOMA:
		return ("homa");
	case SMT_BENCH_PROTO_SMT:
		return ("smt");
	default:
		return ("unknown");
	}
}

const char *
smt_bench_verbose_name(int verbose)
{
	switch (verbose) {
	case -1:
		return ("quiet");
	case 0:
		return ("info");
	case 1:
		return ("debug");
	case 2:
		return ("trace");
	default:
		return ("trace+hexdump");
	}
}

void
smt_bench_setup_signals(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = smt_bench_signal_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) != 0 ||
	    sigaction(SIGTERM, &action, NULL) != 0 ||
	    sigaction(SIGUSR1, &action, NULL) != 0) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL) != 0) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

int
smt_bench_now(struct timespec *now)
{
#ifdef CLOCK_MONOTONIC_PRECISE
	return (clock_gettime(CLOCK_MONOTONIC_PRECISE, now));
#else
	return (clock_gettime(CLOCK_MONOTONIC, now));
#endif
}

double
smt_bench_elapsed_seconds(const struct timespec *start,
    const struct timespec *end)
{
	return ((double)(end->tv_sec - start->tv_sec) +
	    (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0);
}

double
smt_bench_elapsed_us(const struct timespec *start, const struct timespec *end)
{
	return (smt_bench_elapsed_seconds(start, end) * 1000000.0);
}

int
smt_bench_pin_thread(int thread_id, int offset)
{
#ifdef __FreeBSD__
	cpuset_t cpus;
	int cpu, cpu_count, error, selected;

	error = pthread_getaffinity_np(pthread_self(), sizeof(cpus), &cpus);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	cpu_count = 0;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &cpus))
			cpu_count++;
	}
	if (cpu_count == 0) {
		errno = EINVAL;
		return (-1);
	}
	selected = (thread_id + offset) % cpu_count;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &cpus))
			continue;
		if (selected-- == 0)
			break;
	}
	CPU_ZERO(&cpus);
	CPU_SET(cpu, &cpus);
	error = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (cpu);
#else
	(void)thread_id;
	(void)offset;
	errno = ENOTSUP;
	return (-1);
#endif
}

int
smt_bench_resolve_ipv4(const char *host, uint16_t port,
    struct sockaddr_in *peer, char *numeric, size_t numeric_length)
{
	struct addrinfo hints, *addresses, *address;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(host, NULL, &hints, &addresses);
	if (error != 0) {
		errno = EINVAL;
		return (-1);
	}

	address = addresses;
	if (address == NULL ||
	    address->ai_addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
		freeaddrinfo(addresses);
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	memcpy(peer, address->ai_addr, sizeof(*peer));
	peer->sin_len = sizeof(*peer);
	peer->sin_port = htons(port);
	if (inet_ntop(AF_INET, &peer->sin_addr, numeric,
		(socklen_t)numeric_length) == NULL) {
		freeaddrinfo(addresses);
		return (-1);
	}
	freeaddrinfo(addresses);
	return (0);
}

int
smt_bench_fill_payload(void *buffer, size_t length)
{
	const char *pattern;
	unsigned char *bytes;
	ssize_t result;
	size_t offset;
	int fd;

	pattern = getenv("HOMA_ECHO_PAYLOAD");
	if (pattern == NULL || strcmp(pattern, "fixed") == 0) {
		memset(buffer, '?', length);
		return (0);
	}
	if (strcmp(pattern, "mod") == 0) {
		bytes = buffer;
		for (size_t i = 0; i < length; i++)
			bytes[i] = (unsigned char)i;
		return (0);
	}
	if (strcmp(pattern, "random") != 0) {
		errno = EINVAL;
		return (-1);
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return (-1);
	offset = 0;
	while (offset < length) {
		result = read(fd, (char *)buffer + offset, length - offset);
		if (result < 0 && errno == EINTR)
			continue;
		if (result <= 0) {
			if (result == 0)
				errno = EIO;
			close(fd);
			return (-1);
		}
		offset += (size_t)result;
	}
	close(fd);
	return (0);
}

int
smt_bench_hist_init(struct smt_bench_histogram *histogram)
{
	memset(histogram, 0, sizeof(*histogram));
	histogram->bins = calloc(SMT_BENCH_HIST_BINS,
	    sizeof(*histogram->bins));
	return (histogram->bins == NULL ? -1 : 0);
}

void
smt_bench_hist_destroy(struct smt_bench_histogram *histogram)
{
	free(histogram->bins);
	free(histogram->overflow);
	memset(histogram, 0, sizeof(*histogram));
}

int
smt_bench_hist_add(struct smt_bench_histogram *histogram, double rtt_us,
    uint32_t request_bytes, uint32_t response_bytes)
{
	double *new_overflow;
	size_t index, capacity;

	if (rtt_us <= SMT_BENCH_HIST_MAX_US) {
		index = (size_t)(rtt_us / SMT_BENCH_HIST_BIN_WIDTH_US);
		if (index >= SMT_BENCH_HIST_BINS)
			index = SMT_BENCH_HIST_BINS - 1;
		histogram->bins[index]++;
	} else {
		if (histogram->overflow_count == histogram->overflow_capacity) {
			capacity = histogram->overflow_capacity == 0 ?
			    64 :
			    histogram->overflow_capacity * 2;
			new_overflow = realloc(histogram->overflow,
			    capacity * sizeof(*new_overflow));
			if (new_overflow == NULL)
				return (-1);
			histogram->overflow = new_overflow;
			histogram->overflow_capacity = capacity;
		}
		histogram->overflow[histogram->overflow_count++] = rtt_us;
	}

	histogram->count++;
	histogram->sum_us += rtt_us;
	histogram->sum_squares_us += rtt_us * rtt_us;
	histogram->total_request_bytes += request_bytes;
	histogram->total_response_bytes += response_bytes;
	return (0);
}

int
smt_bench_hist_merge(struct smt_bench_histogram *destination,
    const struct smt_bench_histogram *source)
{
	double *new_overflow;
	size_t required;

	for (size_t i = 0; i < SMT_BENCH_HIST_BINS; i++)
		destination->bins[i] += source->bins[i];
	required = destination->overflow_count + source->overflow_count;
	if (required > destination->overflow_capacity) {
		new_overflow = realloc(destination->overflow,
		    required * sizeof(*new_overflow));
		if (new_overflow == NULL)
			return (-1);
		destination->overflow = new_overflow;
		destination->overflow_capacity = required;
	}
	if (source->overflow_count != 0) {
		memcpy(destination->overflow + destination->overflow_count,
		    source->overflow,
		    source->overflow_count * sizeof(*source->overflow));
	}
	destination->overflow_count = required;
	destination->count += source->count;
	destination->sum_us += source->sum_us;
	destination->sum_squares_us += source->sum_squares_us;
	destination->total_request_bytes += source->total_request_bytes;
	destination->total_response_bytes += source->total_response_bytes;
	return (0);
}

double
smt_bench_hist_average(const struct smt_bench_histogram *histogram)
{
	if (histogram->count == 0)
		return (0.0);
	return (histogram->sum_us / (double)histogram->count);
}

double
smt_bench_hist_stddev(const struct smt_bench_histogram *histogram)
{
	double count, numerator;

	if (histogram->count < 2)
		return (0.0);
	count = (double)histogram->count;
	numerator = histogram->sum_squares_us -
	    histogram->sum_us * histogram->sum_us / count;
	return (sqrt(fmax(0.0, numerator / (count - 1.0))));
}

static int
smt_bench_compare_double(const void *left, const void *right)
{
	double a, b;

	a = *(const double *)left;
	b = *(const double *)right;
	return ((a > b) - (a < b));
}

double
smt_bench_hist_percentile(struct smt_bench_histogram *histogram,
    double percentile)
{
	uint64_t cumulative, target;

	if (histogram->count == 0)
		return (0.0);
	target = (uint64_t)ceil(
	    (percentile / 100.0) * (double)histogram->count);
	if (target == 0)
		target = 1;

	cumulative = 0;
	for (size_t i = 0; i < SMT_BENCH_HIST_BINS; i++) {
		cumulative += histogram->bins[i];
		if (cumulative >= target)
			return ((double)i * SMT_BENCH_HIST_BIN_WIDTH_US);
	}

	qsort(histogram->overflow, histogram->overflow_count,
	    sizeof(*histogram->overflow), smt_bench_compare_double);
	target -= cumulative;
	if (target == 0 || target > histogram->overflow_count)
		return (SMT_BENCH_HIST_MAX_US);
	return (histogram->overflow[target - 1]);
}

void
smt_bench_rate_init(struct smt_bench_rate_limit *limit, double rate)
{
	memset(limit, 0, sizeof(*limit));
	limit->rate = rate;
}

double
smt_bench_rate_try_send(struct smt_bench_rate_limit *limit,
    uint32_t bytes)
{
	struct timespec now;
	double elapsed;

	if (limit->rate == 0.0)
		return (0.0);
	if (smt_bench_now(&now) != 0)
		return (-1.0);
	if (limit->last_time.tv_sec == 0 && limit->last_time.tv_nsec == 0) {
		limit->last_time = now;
		limit->budget = bytes;
	}
	elapsed = smt_bench_elapsed_seconds(&limit->last_time, &now);
	limit->last_time = now;
	limit->budget += elapsed * limit->rate;
	if (limit->budget >= bytes) {
		limit->budget -= bytes;
		if (limit->budget > limit->rate)
			limit->budget = limit->rate;
		return (0.0);
	}
	return (((double)bytes - limit->budget) / limit->rate);
}

int
smt_bench_bind_socket(int fd, const char *address, uint16_t port)
{
	struct sockaddr_in local;

	memset(&local, 0, sizeof(local));
	local.sin_len = sizeof(local);
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	if (inet_pton(AF_INET, address, &local.sin_addr) != 1) {
		errno = EINVAL;
		return (-1);
	}
	return (bind(fd, (struct sockaddr *)&local, sizeof(local)));
}

int
smt_bench_enable_tls(int fd, bool server)
{
	return (smt_enable_test_tls(fd, server));
}

ssize_t
smt_bench_read_full(int fd, void *buffer, size_t length)
{
	size_t offset;
	ssize_t received;

	offset = 0;
	while (offset < length) {
		received = read(fd, (char *)buffer + offset, length - offset);
		if (received < 0 && errno == EINTR) {
			if (smt_bench_stop)
				return (-1);
			continue;
		}
		if (received < 0)
			return (-1);
		if (received == 0)
			break;
		offset += (size_t)received;
	}
	return ((ssize_t)offset);
}

ssize_t
smt_bench_write_full(int fd, const void *buffer, size_t length)
{
	size_t offset;
	ssize_t sent;

	offset = 0;
	while (offset < length) {
		sent = write(fd, (const char *)buffer + offset, length - offset);
		if (sent < 0 && errno == EINTR) {
			if (smt_bench_stop)
				return (-1);
			continue;
		}
		if (sent < 0)
			return (-1);
		if (sent == 0) {
			errno = EPIPE;
			return (-1);
		}
		offset += (size_t)sent;
	}
	return ((ssize_t)offset);
}

static int
smt_bench_extract_recv_args(const struct msghdr *message,
    struct smt_bench_recvmsg_args *arguments)
{
	struct cmsghdr *control;

	for (control = CMSG_FIRSTHDR(__DECONST(struct msghdr *, message));
	    control != NULL;
	    control =
		CMSG_NXTHDR(__DECONST(struct msghdr *, message), control)) {
		if (control->cmsg_level == IPPROTO_SMT &&
		    control->cmsg_type == SMT_BENCH_CMSG_TYPE &&
		    control->cmsg_len >= CMSG_LEN(sizeof(*arguments))) {
			memcpy(arguments, CMSG_DATA(control),
			    sizeof(*arguments));
			return (0);
		}
	}
	errno = EBADMSG;
	return (-1);
}

static void
smt_bench_fill_send_control(union smt_bench_send_cmsgbuf *buffer,
    struct msghdr *message, uint64_t id)
{
	struct smt_bench_sendmsg_args arguments;
	struct cmsghdr *control;

	memset(buffer, 0, sizeof(*buffer));
	memset(&arguments, 0, sizeof(arguments));
	arguments.id = id;

	message->msg_control = buffer->buf;
	message->msg_controllen = sizeof(buffer->buf);
	control = &buffer->hdr;
	control->cmsg_level = IPPROTO_SMT;
	control->cmsg_type = SMT_BENCH_CMSG_TYPE;
	control->cmsg_len = CMSG_LEN(sizeof(arguments));
	memcpy(CMSG_DATA(control), &arguments, sizeof(arguments));
}

static ssize_t
smt_bench_send(int fd, const struct sockaddr_in *peer, const void *payload,
    size_t payload_length, uint64_t id)
{
	union smt_bench_send_cmsgbuf control;
	struct iovec vector;
	struct msghdr message;

	memset(&message, 0, sizeof(message));
	vector.iov_base = __DECONST(void *, payload);
	vector.iov_len = payload_length;
	message.msg_name = __DECONST(struct sockaddr_in *, peer);
	message.msg_namelen = sizeof(*peer);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	smt_bench_fill_send_control(&control, &message, id);
	return (sendmsg(fd, &message, 0));
}

ssize_t
smt_bench_send_request(int fd, const struct sockaddr_in *peer,
    const void *payload, size_t payload_length, uint64_t completion_cookie)
{
	union smt_bench_send_cmsgbuf control;
	struct smt_bench_sendmsg_args arguments;
	struct iovec vector;
	struct msghdr message;
	struct cmsghdr *header;

	memset(&control, 0, sizeof(control));
	memset(&arguments, 0, sizeof(arguments));
	memset(&message, 0, sizeof(message));
	arguments.completion_cookie = completion_cookie;
	vector.iov_base = __DECONST(void *, payload);
	vector.iov_len = payload_length;
	message.msg_name = __DECONST(struct sockaddr_in *, peer);
	message.msg_namelen = sizeof(*peer);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.buf;
	message.msg_controllen = sizeof(control.buf);
	header = &control.hdr;
	header->cmsg_level = IPPROTO_SMT;
	header->cmsg_type = SMT_BENCH_CMSG_TYPE;
	header->cmsg_len = CMSG_LEN(sizeof(arguments));
	memcpy(CMSG_DATA(header), &arguments, sizeof(arguments));
	return (sendmsg(fd, &message, 0));
}

ssize_t
smt_bench_send_response(int fd, const struct sockaddr_in *peer,
    const void *payload, size_t payload_length, uint64_t id)
{
	return (smt_bench_send(fd, peer, payload, payload_length, id));
}

ssize_t
smt_bench_recv(int fd, int flags, void *buffer, size_t buffer_length,
    struct sockaddr_in *peer, struct smt_bench_recvmsg_args *arguments)
{
	union smt_bench_recv_cmsgbuf control;
	struct iovec vector;
	struct msghdr message;
	ssize_t received;

	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	memset(peer, 0, sizeof(*peer));
	memset(arguments, 0, sizeof(*arguments));

	vector.iov_base = buffer;
	vector.iov_len = buffer_length;
	message.msg_name = peer;
	message.msg_namelen = sizeof(*peer);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.buf;
	message.msg_controllen = sizeof(control.buf);

	received = recvmsg(fd, &message, flags);
	if (received < 0)
		return (-1);
	if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (smt_bench_extract_recv_args(&message, arguments) != 0)
		return (-1);
	return (received);
}
