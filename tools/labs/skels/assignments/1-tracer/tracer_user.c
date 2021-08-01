#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "tracer.h"

#define DEVICE_PATH	"/dev/tracer"

/*
 * prints error message and exits
 */

static void error(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

/*
 * print use case
 */

static void usage(const char *argv0)
{
	printf("Usage: %s <options>\n options:\n"
			"\ta pid - start tracing $pid\n"
			"\td pid - stop tracing $pid\n", argv0);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int fd;

	if (argc < 3)
		usage(argv[0]);

	if (strlen(argv[1]) != 1)
		usage(argv[0]);

	fd = open(DEVICE_PATH, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	switch (argv[1][0]) {
	case 'a':
		if (ioctl(fd, TRACER_ADD_PROCESS, atoi(argv[2])) < 0) {
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		break;
	case 'd':
		if (ioctl(fd, TRACER_REMOVE_PROCESS, atoi(argv[2])) < 0) {
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		break;
	default:
		error("Wrong parameter");
	}

	close(fd);

	return 0;
}
