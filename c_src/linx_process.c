/*
 * linx_process -- the Port binary backing `Linx.Process`.
 *
 * Linx.Process performs operations that cannot live inside the multithreaded
 * BEAM: clone(), setns(), fork() and execve(). Doing those in the BEAM
 * corrupts the VM (see silo's DESIGN.md for the reasoning), so they run in
 * this separate OS process, spawned via Port.open from Elixir.
 *
 * CONTROL CHANNEL
 * ---------------
 * The Erlang Port is opened with `:nouse_stdio` and `{:packet, 4}`. That
 * leaves fd 0/1/2 free for the workload (P4) and gives us fd 3 (BEAM -> us)
 * and fd 4 (us -> BEAM) for control traffic. Every message is a 4-byte
 * big-endian length prefix followed by an Erlang External Term Format
 * payload; ETF means the BEAM side needs no codec at all.
 *
 * P0 SCAFFOLDING
 * --------------
 * This is the smallest useful version. It reads one frame on fd 3, ignores
 * its contents, writes the atom :pong on fd 4, and exits 0. The purpose is
 * to prove three things end-to-end:
 *
 *   1. The Mix compiler builds the binary into priv/linx_process.
 *   2. Erlang's Port machinery can spawn it and exchange {:packet, 4}
 *      frames in both directions.
 *   3. The ETF framing on the wire matches what Elixir produces and
 *      consumes.
 *
 * The real clone/setns/execve logic, the checkpoint protocol, and the
 * {:status, ...} / {:error, ...} vocabulary all land in P1+.
 *
 * EXIT CODES
 * ----------
 *   0  success (one frame in, one frame out, clean shutdown)
 *   1  read failure on fd 3 (EOF, error, or oversized frame)
 *   2  write failure on fd 4
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define CTL_IN	3
#define CTL_OUT	4

/* The ETF encoding of the atom :pong as a complete term.
 *   131  -- ETF version byte
 *   119  -- SMALL_ATOM_UTF8_EXT
 *   4    -- length in bytes
 *   p o n g                                                                  */
static const uint8_t etf_pong[] = { 131, 119, 4, 'p', 'o', 'n', 'g' };

/* Read `count` bytes from `fd` into `buf`, looping past short reads and
 * EINTR. Returns 0 on success, -1 on error or EOF. EOF is reported as -1
 * with errno cleared. */
static int read_exact(int fd, void *buf, size_t count)
{
	uint8_t *p = buf;
	while (count > 0) {
		ssize_t n = read(fd, p, count);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			errno = 0;
			return -1;
		}
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

/* Symmetric to read_exact for write(2). */
static int write_exact(int fd, const void *buf, size_t count)
{
	const uint8_t *p = buf;
	while (count > 0) {
		ssize_t n = write(fd, p, count);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

/* Write a {:packet, 4}-framed message of `len` bytes from `buf` to fd 4. */
static int write_frame(const void *buf, uint32_t len)
{
	uint8_t hdr[4] = {
		(uint8_t)(len >> 24), (uint8_t)(len >> 16),
		(uint8_t)(len >> 8),  (uint8_t)len,
	};
	if (write_exact(CTL_OUT, hdr, sizeof hdr) < 0)
		return -1;
	return write_exact(CTL_OUT, buf, len);
}

/* Read one {:packet, 4}-framed message from fd 3 into `buf` (capacity
 * `cap`). Returns the message length, or -1 on error/EOF. An oversized
 * frame is reported as -1 with errno set to EMSGSIZE. */
static ssize_t read_frame(void *buf, size_t cap)
{
	uint8_t hdr[4];
	if (read_exact(CTL_IN, hdr, sizeof hdr) < 0)
		return -1;
	uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
		       ((uint32_t)hdr[2] << 8)  | (uint32_t)hdr[3];
	if (len > cap) {
		errno = EMSGSIZE;
		return -1;
	}
	if (read_exact(CTL_IN, buf, len) < 0)
		return -1;
	return (ssize_t)len;
}

int main(void)
{
	/* P0: ignore whatever the BEAM sends, reply :pong. The real
	 * command vocabulary (`:proceed`, `{:signal, n}`, …) arrives in
	 * P1+ along with ETF decoding logic. */
	uint8_t buf[1024];
	if (read_frame(buf, sizeof buf) < 0) {
		fprintf(stderr, "linx_process: read frame: %s\n",
			errno ? strerror(errno) : "eof");
		return 1;
	}

	if (write_frame(etf_pong, sizeof etf_pong) < 0) {
		fprintf(stderr, "linx_process: write frame: %s\n",
			strerror(errno));
		return 2;
	}

	return 0;
}
