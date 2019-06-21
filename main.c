/*
 * Utility to check and format dm-integrity metadata
 *
 * Copyright (C) 2016, Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <math.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <getopt.h>

#define SECTOR_SIZE 512

#define log_dbg(x...) if (_debug) printf(x);

/* Integrity superblock */
#define SB_MAGIC	"integrt"
#define SB_VERSION	1

struct superblock {
	uint8_t magic[8];
	uint8_t version;
	int8_t log2_interleave_sectors;
	uint16_t integrity_tag_size;
	uint32_t journal_sections;
	uint64_t provided_data_sectors;
} __attribute__ ((packed));

static enum { CMD_DUMP, CMD_CHECK, CMD_FIX, CMD_FORMAT } command;
typedef enum { DEV_CHECK, DEV_FIX, DEV_FORMAT } dev_command;

static int _debug = 0, _randomize = 0, open_flags = O_DIRECT;

static unsigned int block_sectors = 8192; /* 16 MB */

static void *aligned_malloc(void **base, int size)
{
	return posix_memalign(base, 8192, size) ? NULL : *base;
}

static void get_random(void *buf, size_t buf_size)
{
	int r;

	do {
		r = syscall(SYS_getrandom, buf, buf_size, 0);
		assert((size_t)r <= buf_size);
		assert(!errno || errno == EINTR);

		if (r > 0) {
			buf = (char*)buf + r;
			buf_size -= r;
		}

	} while (buf_size);
}

static int device_size_sec(const char *device, uint64_t *size)
{
	struct stat st;
	int devfd, r = 0;

	if (stat(device, &st) < 0)
		return -EINVAL;

	devfd = open(device, O_RDONLY);
	if(devfd == -1)
		return -EINVAL;

	if (ioctl(devfd, BLKGETSIZE64, size) < 0)
		r = -EINVAL;

	*size /= SECTOR_SIZE;

	close(devfd);
	return r;
}

static void init_sector(char *sf)
{
	if (_randomize)
		get_random(sf, SECTOR_SIZE);
	else
		memset(sf, 0, SECTOR_SIZE);
}

/* The difference in seconds between two times in "timeval" format. */
static double time_diff(struct timeval start, struct timeval end)
{
	return (end.tv_sec - start.tv_sec)
		+ (end.tv_usec - start.tv_usec) / 1E6;
}

static void clear_line(void)
{
	/* vt100 code clear line */
	printf("\33[2K\r");
}

static void print_progress(uint64_t device_size, uint64_t bytes, int final)
{
	static struct timeval start_time = {}, now_time = {}, end_time = {};
	unsigned long long mbytes, eta;
	double tdiff, mib;

	gettimeofday(&now_time, NULL);
	if (start_time.tv_sec == 0 && start_time.tv_usec == 0) {
		start_time = now_time;
		end_time = now_time;
		return;
	}

	if (!final && time_diff(end_time, now_time) < 0.5)
		return;

	end_time = now_time;

	tdiff = time_diff(start_time, end_time);
	if (!tdiff)
		return;

	mbytes = bytes  / 1024 / 1024;
	mib = (double)(mbytes) / tdiff;
	if (!mib)
		return;

	/* FIXME: calculate this from last minute only and remaining space */
	eta = (unsigned long long)(device_size / 1024 / 1024 / mib - tdiff);

	clear_line();
	if (final)
		printf("Finished, time %02llu:%02llu.%03llu, "
			"%4llu MiB written, speed %5.1f MiB/s\n",
			(unsigned long long)tdiff / 60,
			(unsigned long long)tdiff % 60,
			(unsigned long long)((tdiff - floor(tdiff)) * 1000.0),
			mbytes, mib);
	else
		printf("Progress: %5.1f%%, ETA %02llu:%02llu, "
			"%4llu MiB written, speed %5.1f MiB/s",
			(double)bytes / device_size * 100,
			eta / 60, eta % 60, mbytes, mib);
	fflush(stdout);
}

static void check_one_by_one(int devfd, char *sf, uint64_t block_size_sec,
			     uint64_t offset_sec, dev_command dc)
{
	ssize_t size;
	uint64_t sector;

	clear_line();

	for (sector = offset_sec; sector < (offset_sec + block_size_sec); sector++) {

		if (lseek64(devfd, sector * SECTOR_SIZE, SEEK_SET) < 0) {
			printf("Seek error, sector %" PRIu64 " (Errno %d).\n", sector, errno);
			return;
		}

		size = read(devfd, sf, SECTOR_SIZE);
		if (size == SECTOR_SIZE)
			continue;

		if (errno != EIO && errno != EILSEQ) {
			printf("Error sector %" PRIu64 " (Errno %d).\n", sector, errno);
			return;
		}

		if (dc != DEV_FIX) {
			printf("IO error sector %" PRIu64 ".\n", sector);
			continue;
		}

		/* Try to overwrite sector */
		init_sector(sf);

		if (lseek64(devfd, sector * SECTOR_SIZE, SEEK_SET) < 0) {
			printf("Seek error, sector %" PRIu64 " (Errno %d).\n", sector, errno);
			continue;
		}

		size = write(devfd, sf, SECTOR_SIZE);
		if (size != SECTOR_SIZE)
			printf("Error sector %" PRIu64 " (Errno %d).\n", sector, errno);
		else
			printf("Bad sector %" PRIu64 " wiped.\n", sector);
	}
	fflush(stdout);
}

static int rw_sectors(const char *device, uint64_t offset_sec,
		      uint64_t dev_size_sec, dev_command dc)
{
	ssize_t size;
	uint64_t block_size_sec, sector;
	void *x;
	char *sf;
	int devfd, flags = open_flags;

	sf = aligned_malloc(&x, block_sectors * SECTOR_SIZE);
	if (!sf)
		return EXIT_FAILURE;

	if (dc == DEV_CHECK)
		flags |= O_RDONLY;
	else
		flags |= O_RDWR;

	devfd = open(device, flags);
	if (devfd == -1) {
		free (sf);
		return EXIT_FAILURE;
	}

	while (offset_sec < dev_size_sec) {
		if ((offset_sec + block_sectors) > dev_size_sec)
			block_size_sec = dev_size_sec - offset_sec;
		else
			block_size_sec = block_sectors;

		if (lseek64(devfd, offset_sec * SECTOR_SIZE, SEEK_SET) < 0) {
			printf("Seek error, sector %" PRIu64 " (Errno %d).\n", offset_sec, errno);
			close(devfd);
			free (sf);
			return EXIT_FAILURE;
		}

		if (dc == DEV_FORMAT) {
			log_dbg("Wipe %"PRIu64"-%"PRIu64"\n", offset_sec, offset_sec + block_size_sec);
			for (sector = 0; sector < block_size_sec; sector++)
				init_sector(&sf[sector * SECTOR_SIZE]);

			size = write(devfd, sf, SECTOR_SIZE * block_size_sec);
			if (size != (ssize_t)(SECTOR_SIZE * block_size_sec))
				printf("Write error, sector %" PRIu64 ".\n", offset_sec);
		} else {
			size = read(devfd, sf, SECTOR_SIZE * block_size_sec);
			if (size != (ssize_t)(SECTOR_SIZE * block_size_sec))
				check_one_by_one(devfd, sf, block_size_sec, offset_sec, dc);
		}

		offset_sec += block_size_sec;
		print_progress(dev_size_sec * SECTOR_SIZE, offset_sec * SECTOR_SIZE, 0);
	}

	if (fsync(devfd) < 0)
		printf("FSYNC failed, errno %d.\n", errno);

	close(devfd);
	free(sf);

	print_progress(dev_size_sec * SECTOR_SIZE, offset_sec * SECTOR_SIZE, 1);

	return 0;
}

static int read_superblock(const char *device, struct superblock *sb)
{
	int devfd, r;

	if (!device)
		return EXIT_FAILURE;

	devfd = open(device, O_RDONLY);
	if(devfd == -1)
		return EXIT_FAILURE;

	if (read(devfd, sb, sizeof(*sb)) != sizeof(*sb) ||
	    memcmp(sb->magic, SB_MAGIC, sizeof(sb->magic)) ||
	    sb->version != SB_VERSION) {
		printf("No header detected in %s.\n", device);
		r = EXIT_FAILURE;
	} else {
		sb->integrity_tag_size = le16toh(sb->integrity_tag_size);
		sb->journal_sections = le32toh(sb->journal_sections);
		sb->provided_data_sectors = le64toh(sb->provided_data_sectors);
		r = EXIT_SUCCESS;
	}

	close(devfd);
	return r;
}

static int cmd_dump(const char *device)
{
	struct superblock sb;
	int r;

	r = read_superblock(device, &sb);
	if (r)
		return r;
	printf("Info for integrity device %s.\n", device);
	printf("log2_interleave_sectors %d\n", sb.log2_interleave_sectors);
	printf("integrity_tag_size %u\n", sb.integrity_tag_size);
	printf("journal_sections %u\n", sb.journal_sections);
	printf("provided_data_sectors %" PRIu64 "\n", sb.provided_data_sectors);

	return EXIT_SUCCESS;
}

static int cmd_dev(const char *device, dev_command dc)
{
	uint64_t dev_size_sec;

	log_dbg("Running check %s.\n", device);
	if (device_size_sec(device, &dev_size_sec))
		return EXIT_FAILURE;

	return rw_sectors(device, 0, dev_size_sec, dc);
}

static void __attribute__((__noreturn__)) help(void)
{
	printf("Use: [--debug] [--randomize] [--blocksize <sectors>] [--no-direct] dump|check|fix|format <device>.\n"
		"\nCommands:\n"
		"  dump   - dump dm-integrity superblock\n"
		"  check  - use direct-io to check device access\n"
		"  fix    - check and rewrite sectors with IO errors\n"
		"  format - fix the whole device\n"
		"\nDevice is wiped with zeroes or with random data if --randomize is used.\n");
	exit(EXIT_FAILURE);
}

int main (int argc, char *argv[])
{
	int c;
	long long tmpll;
	static const struct option longopts[] = {
		{ "blocksize",  required_argument, 0, 'b' },
		{ "no-direct",  no_argument,       0, 'n' },
		{ "randomize",  no_argument,       0, 'r' },
		{ "debug",      no_argument,       0, 'd' },
		{ "help",       no_argument,       0, 'h' },
		{ NULL, 0, 0, 0 },
	};

	while((c = getopt_long(argc, argv, "b:rdhn", longopts, NULL)) != -1) {
		switch(c) {
		case 'b':
			tmpll = atoll(optarg);
			block_sectors = (uint64_t)tmpll;
			if (tmpll <= 0 || tmpll != (long long)block_sectors)
				help();
			break;
		case 'n':
			open_flags = 0;
			break;
		case 'd':
			_debug = 1;
			break;
		case 'r':
			_randomize = 1;
			break;
		case 'h':
		default:
			help();
		}
	}

	if (optind >=  argc)
		help();

	if (!strcmp(argv[optind], "dump"))
		command = CMD_DUMP;
	else if (!strcmp(argv[optind], "check"))
		command = CMD_CHECK;
	else if (!strcmp(argv[optind], "fix"))
		command = CMD_FIX;
	else if (!strcmp(argv[optind], "format"))
		command = CMD_FORMAT;
	else
		help();

	if (++optind >=  argc)
		help();

	switch (command) {
	case CMD_DUMP:
		return cmd_dump(argv[optind]);
	case CMD_CHECK:
		return cmd_dev(argv[optind], DEV_CHECK);
	case CMD_FIX:
		return cmd_dev(argv[optind], DEV_FIX);
	case CMD_FORMAT:
		return cmd_dev(argv[optind], DEV_FORMAT);
	}

	return EXIT_FAILURE;
}
