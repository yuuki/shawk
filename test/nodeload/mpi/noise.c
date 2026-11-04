/*
 * A latency-bound MPI benchmark for the measurements of #172: N iterations
 * of an MPI_Allreduce of 8 bytes over all ranks, each timed by rank 0.
 * Any rank delayed by noise (another task on its CPU, an interrupt) delays
 * the iteration for all, so the tail of the iterations and the run time
 * show the noise of all nodes.
 *
 *   mpicc -O2 -o noise noise.c
 *   srun --mpi=pmix ./noise [ITERATIONS [LABEL]]
 *
 * Rank 0 prints a JSON line: the run time, and the percentiles of the
 * iterations in microseconds.
 */
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 200000, i, over1 = 0, over10 = 0;
	const char *label = argc > 2 ? argv[2] : "";
	int rank, size;
	double x = 1, y, t0, start, total, *dt;

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	dt = malloc(n * sizeof(*dt));
	if (!dt)
		MPI_Abort(MPI_COMM_WORLD, 1);
	/* Warm up: connect all ranks before the clock starts. */
	for (i = 0; i < 1000; i++)
		MPI_Allreduce(&x, &y, 1, MPI_DOUBLE, MPI_SUM, MPI_COMM_WORLD);
	MPI_Barrier(MPI_COMM_WORLD);
	start = MPI_Wtime();
	for (i = 0; i < n; i++) {
		t0 = MPI_Wtime();
		MPI_Allreduce(&x, &y, 1, MPI_DOUBLE, MPI_SUM, MPI_COMM_WORLD);
		dt[i] = (MPI_Wtime() - t0) * 1e6;
	}
	total = MPI_Wtime() - start;
	if (rank == 0) {
		for (i = 0; i < n; i++) {
			over1 += dt[i] > 1000;
			over10 += dt[i] > 10000;
		}
		qsort(dt, n, sizeof(*dt), cmp);
		printf("{\"label\":\"%s\",\"ranks\":%d,\"iterations\":%ld,\"run_s\":%.4f,"
		       "\"mean_us\":%.2f,\"p50_us\":%.1f,\"p99_us\":%.1f,\"p999_us\":%.1f,"
		       "\"p9999_us\":%.1f,\"max_us\":%.1f,\"over_1ms\":%ld,\"over_10ms\":%ld}\n",
		       label, size, n, total, total * 1e6 / n, dt[n / 2], dt[n * 99 / 100],
		       dt[n * 999 / 1000], dt[n * 9999 / 10000], dt[n - 1], over1, over10);
	}
	free(dt);
	MPI_Finalize();
	return 0;
}
