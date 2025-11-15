#include "rtts.h"

static int compare_doubles(const void* a, const void* b) {
  double arg1 = *(const double*)a;
  double arg2 = *(const double*)b;
  if (arg1 < arg2) return -1;
  if (arg1 > arg2) return 1;
  return 0;
}

#define PRIMARY_BIN_MAX 10000
#define DATA_DECIMAL_PRECISION 100  // For 0.01us precision

// Function to create and initialize the histogram
struct histogram create_histogram(void) {
  struct histogram hist;
  hist.primary_size = PRIMARY_BIN_MAX * DATA_DECIMAL_PRECISION;
  hist.primary_bins = calloc(hist.primary_size, sizeof(size_t));
  malloc_check(hist.primary_bins);
  hist.overflow_numbers = NULL;
  hist.overflow_size = 0;
  hist.overflow_capacity = 0;
  hist.preheat = 0;
  hist.total_data_points = 0;
  hist.total_req_size = 0.0;
  hist.total_resp_size = 0.0;
  return hist;
}

struct histogram create_histogram_with_preheat(int preheat) {
  struct histogram hist = create_histogram();
  hist.preheat = preheat;
  return hist;
}

// Function to add data to the histogram
void add_data(struct histogram *hist, double data) {
  if (hist->preheat > 0) {
    hist->preheat--;
    return;
  }
  if (data >= 0.00 && data <= PRIMARY_BIN_MAX) {
    size_t index = (size_t)(data * DATA_DECIMAL_PRECISION);
    hist->primary_bins[index]++;
  } else {
    log_trace("overflow datapoint inserted (%.2lf)", data);
    if (hist->overflow_size >= hist->overflow_capacity) {
      hist->overflow_capacity = hist->overflow_capacity > 0 ? hist->overflow_capacity * 2 : 1;
      hist->overflow_numbers = realloc(hist->overflow_numbers, hist->overflow_capacity * sizeof(double));
      malloc_check(hist->overflow_numbers);
    }
    hist->overflow_numbers[hist->overflow_size++] = data;
  }
}

void add_total_size(struct histogram *hist, double reqlen, double resplen) {
  hist->total_data_points++;
  hist->total_req_size += reqlen;
  hist->total_resp_size += resplen;
}

void add_rtt(struct histogram *hist, struct timespec a, struct timespec b, uint32_t reqlen, uint32_t resplen) {
  add_data(hist, calculate_time_delta_us(a, b));
  add_total_size(hist, (double)reqlen, (double)resplen);
}

void merge_overflow(struct histogram *dest, double *overflow_data, size_t overflow_size) {
  if (overflow_size == 0) {
    return;
  }

  if (dest->overflow_size + overflow_size > dest->overflow_capacity) {
    dest->overflow_capacity = (dest->overflow_size + overflow_size) * 2;
    dest->overflow_numbers = realloc(dest->overflow_numbers, dest->overflow_capacity * sizeof(double));
    malloc_check(dest->overflow_numbers);
  }
  memcpy(dest->overflow_numbers + dest->overflow_size, overflow_data, overflow_size * sizeof(double));
  dest->overflow_size += overflow_size;
}

// Function to merge multiple histograms into a single histogram
void merge_histograms(struct histogram *dest, struct histogram *srcs, size_t num_srcs) {
  for (size_t i = 0; i < num_srcs; i++) {
    struct histogram *src = &srcs[i];
    // Accumulate the total data points from all histograms
    dest->total_data_points += src->total_data_points;
    dest->total_req_size += src->total_req_size;
    dest->total_resp_size += src->total_resp_size;
    for (size_t j = 0; j < src->primary_size; j++) {
      dest->primary_bins[j] += src->primary_bins[j];
    }
    // Merge overflow data directly
    merge_overflow(dest, src->overflow_numbers, src->overflow_size);
  }
}

void free_histogram(struct histogram *hist) {
  if (hist->primary_bins != NULL) {
    free(hist->primary_bins);
    hist->primary_bins = NULL;  // Prevent use-after-free
  }
  hist->primary_size = 0;
  if (hist->overflow_numbers != NULL) {
    free(hist->overflow_numbers);
    hist->overflow_numbers = NULL;  // Prevent use-after-free
  }
  hist->overflow_size = 0;
  hist->overflow_capacity = 0;
  hist->preheat = 0;
  hist->total_data_points = 0;
  hist->total_req_size = 0.0;
  hist->total_resp_size = 0.0;
}

double calculate_average(struct histogram *hist) {
  double sum = 0.0;

  if (hist->total_data_points == 0)
    return sum;

  // Sum all times from the primary bins
  for (size_t i = 0; i < hist->primary_size; i++) {
    if (hist->primary_bins[i] > 0) {
      sum += i / (double)DATA_DECIMAL_PRECISION * hist->primary_bins[i];
    }
  }

  // Sum all times from the overflow bins
  for (size_t i = 0; i < hist->overflow_size; i++) {
    sum += hist->overflow_numbers[i];
  }

  return sum / (double)hist->total_data_points;
}

double calculate_stddev(struct histogram *hist, double *precalc_avg) {
    double avg = 0.0;
    if (precalc_avg) {
      avg = *precalc_avg;
    } else {
      avg = calculate_average(hist);
    }

    double sum_sq_diff = 0.0;

    for (size_t i = 0; i < hist->primary_size; i++) {
      if (hist->primary_bins[i] > 0) {
        double diff = (i / (double)DATA_DECIMAL_PRECISION) - avg;
        sum_sq_diff += diff * diff * hist->primary_bins[i];
      }
    }

    for (size_t i = 0; i < hist->overflow_size; i++) {
        double diff = hist->overflow_numbers[i] - avg;
        sum_sq_diff += diff * diff;
    }

    if (hist->total_data_points == 0)
        return 0.0;

    double variance = sum_sq_diff / (hist->total_data_points - 1);

    return sqrt(variance);
}

// Function to calculate a percentile
void calculate_percentiles(struct histogram *hist, double percentiles[], double results[], size_t num_percentiles) {
  size_t total_count = hist->total_data_points;

  // Sort overflow bins if necessary
  if (hist->overflow_size > 0) {
    qsort(hist->overflow_numbers, hist->overflow_size, sizeof(double), compare_doubles);
  }

  // Calculate each requested percentile
  for (size_t p = 0; p < num_percentiles; p++) {
    size_t target_count = (size_t)(total_count * percentiles[p] / 100.0);
    size_t cumulative_count = 0;
    size_t i;

    // Check primary bins first
    for (i = 0; i < hist->primary_size; i++) {
      cumulative_count += hist->primary_bins[i];
      if (cumulative_count >= target_count) {
      results[p] = i / (double)DATA_DECIMAL_PRECISION;
          break;
      }
    }

    // Check overflow bins if necessary
    if (i == hist->primary_size && hist->overflow_size > 0) {
      for (size_t j = 0; j < hist->overflow_size; j++) {
        cumulative_count++;
        if (cumulative_count >= target_count) {
          results[p] = hist->overflow_numbers[j];
          break;
        }
      }
    }
  }
}

/*
int main() {
  srand(time(NULL));

  int num_histograms = 1;
  struct histogram histograms[num_histograms];

  struct timespec start_time, end_time;
  double add_time = 0.0;

  clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);

  for (size_t i = 0; i < num_histograms; i++)
  {
    histograms[i] = create_histogram();

    for (int j = 0; j < 50000; j++) {
      double val = 0.0;
      if (j % 5 == 0) {  // Add some overflow data
        val = (float)PRIMARY_BIN_MAX * (1 + (float) rand() / (float) RAND_MAX);
      } else {
        val = (float)PRIMARY_BIN_MAX * ((float) rand() / (float) RAND_MAX);
      }
      add_data(&histograms[i], val);
    }
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);

  printf("Add time per rtt: %.2f us\n\n", calculate_time_delta_us(start_time, end_time) / 50000);

  // Create a new histogram to store the combined results
  struct histogram combined_hist = create_histogram();

  // Merge all histograms into one
  merge_histograms(&combined_hist, histograms, num_histograms);

  printf("Average RTT: %.2f us\n", calculate_average(&combined_hist));

  double percentiles[] = {50.0, 95.0, 99.0};
  double results[3];
  calculate_percentiles(&combined_hist, percentiles, results, 3);

  printf("P50: %.2f us\n", results[0]);
  printf("P95: %.2f us\n", results[1]);
  printf("P99: %.2f us\n", results[2]);
  printf("Total data points: %zu\n", combined_hist.total_data_points);  // Print the total number of data points

  for (size_t i = 0; i < num_histograms; i++) {
    free_histogram(&histograms[i]);
  }
  free_histogram(&combined_hist);

  return 0;
}
*/
