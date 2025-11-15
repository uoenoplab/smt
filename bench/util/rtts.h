#ifndef _RTTS_H
#define _RTTS_H

#include "utils.h"

struct histogram {
  size_t *primary_bins;
  size_t primary_size;
  double *overflow_numbers;
  size_t overflow_size;
  size_t overflow_capacity;
  size_t preheat;
  size_t total_data_points;
  double total_req_size;
  double total_resp_size;
};

void add_rtt(struct histogram *hist, struct timespec a, struct timespec b, uint32_t reqlen, uint32_t resplen);

double calculate_average(struct histogram *hist);
double calculate_stddev(struct histogram *hist, double *precalc_avg);
void calculate_percentiles(struct histogram *hist, double percentiles[], double results[], size_t num_percentiles);

struct histogram create_histogram(void);
struct histogram create_histogram_with_preheat(int preheat);
void merge_histograms(struct histogram *dest, struct histogram *srcs, size_t num_srcs);
void free_histogram(struct histogram *hist);

#endif /* _RTTS_H */
