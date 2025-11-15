/*
 * Copyright (c) 2024 Tianyi Gao <gao.tianyi@outlook.com>
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "log.h"

static struct {
  void *udata;
  int level;
} L;


static const char *level_strings[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

#ifdef LOG_USE_COLOR
static const char *level_colors[] = {
  "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};
#endif

void log_set_level(int level) {
  L.level = level;
}

void log_log(int level, const char *file, int line, const char *func, const char *fmt, ...) {
  if (level < L.level) return;

  struct timespec t_ts;
  clock_gettime(CLOCK_REALTIME, &t_ts);

  struct tm t_tm;
  gmtime_r(&t_ts.tv_sec, &t_tm);

  char hms[16];
  strftime(hms, sizeof(hms), "%H:%M:%S", &t_tm);

  char nsec[10];
  snprintf(nsec, sizeof(nsec), ".%06ld", t_ts.tv_nsec / 1000);

  pid_t p = syscall(__NR_gettid);

#ifdef LOG_USE_COLOR
  fprintf(
    stdout, "[%s%s][%s%s\x1b[0m][\x1b[90m%s:%d\x1b[0m][%s][%06d] ",
    hms, nsec, level_colors[level], level_strings[level],
    file, line, func, p);
#else
  fprintf(
    stdout, "[%s%s][%s][%s:%d][%s][%06d] ",
    hms, nsec, level_strings[level], file, line, func, p);
#endif

  va_list args;
  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  fprintf(stdout, "\n");
  fflush(stdout);
  va_end(args);
}
