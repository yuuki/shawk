/*
 * MPI_Alltoall of 8 bytes per pair of ranks, in a loop for SECONDS, so that
 * every pair of ranks holds a connection, for the flows of MPI over TCP of
 * #172 (mpi.sh).
 *
 *   mpicc -O2 -o alltoall alltoall.c
 *   srun --mpi=pmix ./alltoall [SECONDS]
 */
#include <mpi.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	double secs = argc > 1 ? atof(argv[1]) : 60, start;
	int size, done = 0;
	double *in, *out;

	MPI_Init(&argc, &argv);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	in = calloc(size, sizeof(*in));
	out = calloc(size, sizeof(*out));
	start = MPI_Wtime();
	while (!done) {
		MPI_Alltoall(out, 1, MPI_DOUBLE, in, 1, MPI_DOUBLE, MPI_COMM_WORLD);
		/* All ranks stop at the same iteration. */
		done = MPI_Wtime() - start > secs;
		MPI_Allreduce(MPI_IN_PLACE, &done, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
	}
	free(in);
	free(out);
	MPI_Finalize();
	return 0;
}
