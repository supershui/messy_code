/*
 * Works only in Linux (reads /dev/urandom).
 * Example:
 * gcc -Wall mem_err_check.c -o mem_err_check
 * ./mem_err_check --mem-size 10G --round 100
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <time.h>
#include <sys/time.h>


typedef struct _err_rec {
	int src;
	int dest;
	long index;
	unsigned long write_bytes_low;
	unsigned long write_bytes_high;
	int mode;
	char random;
} ErrRec;

typedef struct _my_list {
	void *content;
	struct _my_list *next;
} MyList;


typedef struct _mem_check_profile {
	long mem_block_size;
	long actual_mem_block_size;
	int rounds;
	int inner_loops;

	int current_mode;
	char current_random;

	unsigned long total_write_bytes_low;
	unsigned long total_write_bytes_high;
	int error_count;

} MemCheckProfile;


const char* const PARAM_KEY_MEM_SIZE = "--mem-size";
const char* const PARAM_KEY_ROUND = "--round";


MemCheckProfile g_mem_check_profile;

MyList *g_error_records_ptr = NULL;
MyList *g_error_records_tail_ptr = NULL;

/* 2022-02-22 22:22:22.222222 */
char current_time_buf[24] = {0};
void zero_time_buf(char* output) {
	snprintf(output, 27,
		"%04d-%02d-%02d %02d:%02d:%02d.%06ld",
		0, 0, 0, 0, 0, 0, 0L);
}
char* make_current_time_str(char* output) {
	struct timeval tv;
	int result = gettimeofday(&tv, NULL);

	if (output == NULL) {
		output = current_time_buf;
	}

	if (result == 0) {
		struct tm *ptm = localtime(&(tv.tv_sec));
		if (ptm != NULL) {
			snprintf(output, 27,
				"%04d-%02d-%02d %02d:%02d:%02d.%06ld",
				ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
				ptm->tm_hour, ptm->tm_min, ptm->tm_sec, tv.tv_usec);
		} else {
			zero_time_buf(output);
		}
	} else {
		zero_time_buf(output);
	}

	return output;
}

int log_fd = -1;
void append_to_log_file(char *content, int len) {
	if (log_fd < 0) {
		const int fn_len = 33;
		char fn[fn_len];
		struct timeval tv;
		int tv_result = gettimeofday(&tv, NULL);
		if (tv_result == 0) {
			struct tm *ptm = localtime(&(tv.tv_sec));
			if (ptm != NULL) {
				snprintf(fn, fn_len, "check_result_%04d%02d%02d_%02d%02d%02d.log",
						ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
						ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
			} else {
				snprintf(fn, 32, "%s", "check_result.log");
			}
		} else {
			snprintf(fn, 32, "%s", "check_result.log");
		}
		log_fd = open(fn, O_APPEND | O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IROTH);
		if (log_fd < 0) {
			return;
		}
		printf("save log to %s.\n", fn);
	}


	int cnt = 0, n;
	while (cnt < len) {
		n = write(log_fd, content + cnt, len);
		if (n > 0) {
			cnt += n;
		} else if (n < 0) {
			break;
		}
	}
}

void print_logln(const char *format, ...) {
	const int len = 4096;
	char *line = (char *) malloc(len);
	char *time_str = make_current_time_str(line);
	if (line == NULL) {
		printf("%s: no memory to format message.\n", time_str);
		return;
	}

	int offset = strlen(line);
	if (format == NULL) {
		line[offset++] = ':';
		line[offset++] = '\n';
		line[offset++] = '\0';
	} else {
		line[offset++] = ':';
		line[offset++] = ' ';
		va_list arg;
		va_start(arg, format);
		int end = vsnprintf(line + offset, len - offset, format, arg);
		va_end(arg);
		int remainder = len - offset - end;
		if (remainder > 2) {
			line[offset + end++] = '\n';
			line[offset + end++] = '\0';
		}
	}
	printf("%s", line);
	append_to_log_file(line, strlen(line));
	free(line);
}

void print_log(char *format, ...) {
	const int len = 4096;
	char *line = (char *) malloc(len);
	char *time_str = make_current_time_str(line);
	if (line == NULL) {
		printf("%s: no memory to format message.\n", time_str);
		return;
	}

	int offset = strlen(line);
	if (format == NULL) {
		line[offset++] = ':';
		line[offset++] = '\0';
	} else {
		line[offset++] = ':';
		line[offset++] = ' ';
		va_list arg;
		va_start(arg, format);
		vsnprintf(line + offset, len - offset, format, arg);
		va_end(arg);
	}
	printf("%s", line);
	append_to_log_file(line, strlen(line));
	free(line);
}

void intToBinStr(char *bin_str, int n) {
	for (int i = 0; i < 32; i++) {
		bin_str[i] = (n & 0x80000000) == 0 ? '0' : '1';
		n <<= 1;
	}
	bin_str[32] = '\0';
}

long parse_mem_size(char *mem_size_str) {
	print_logln("parse_mem_size: mem_size=%s", mem_size_str);
	int len = strlen(mem_size_str);
	if (len < 1) {
		print_logln("parse_mem_size: len=%d", len);
		return -1L;
	}

	char unit = mem_size_str[len - 1];
	long factor = 1;
	switch (unit) {
		case 'K':
		case 'k': {
			factor = 1024L;
			break;
		}
		case 'M':
		case 'm': {
			factor = 1024L * 1024L;
			break;
		}
		case 'G':
		case 'g': {
			factor = 1024L * 1024L * 1024L;
			break;
		}
		case 'T':
		case 't': {
			factor = 1024L * 1024L * 1024L * 1024L;
			break;
		}
		case 'P':
		case 'p': {
			factor = 1024L * 1024L * 1024L * 1024L * 1024L;
			break;
		}
		case 'E':
		case 'e': {
			factor = 1024L * 1024L * 1024L * 1024L * 1024L * 1024L;
			break;
		}
		// Z and Y are beyond long range.
	}

	long size = -1;
	int n = sscanf(mem_size_str, "%ld", &size);
	if (n < 1) {
		print_logln("parse_mem_size: can not read memory size from %s.", mem_size_str);
		return -1L;
	}
	if (size < 1) {
		print_logln("parse_mem_size: invalid size %ld.", size);
		return -1L;
	}

	return size * factor;
}

int parse_rounds(char *rounds_str) {
	int rounds = -1;
	int n = sscanf(rounds_str, "%d",  &rounds);
	if (n < 1) {
		print_logln("parse_rounds: can not read rounds from %s.", rounds_str);
		return -1;
	}
	if (n < 1) {
		print_logln("parse_rounds: invalid rounds %d.", rounds);
		return -1;
	}
	return rounds;
}

int parse_args(int argc, char* argv[]) {
	long mem_size = -1;
	int rounds = -1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(PARAM_KEY_MEM_SIZE, argv[i]) == 0) {
			i++;
			if (i < argc) {
				mem_size = parse_mem_size(argv[i]);
			}
		} else if (strcmp(PARAM_KEY_ROUND, argv[i]) == 0) {
			i++;
			if (i < argc) {
				rounds = parse_rounds(argv[i]);
			}
		} else {
			print_logln("parse_args: unrecognized param %s", argv[i]);
		}
	}

	if (mem_size < 1) {
		return -1;
	}
	if (rounds < 1) {
		return -2;
	}

	g_mem_check_profile.mem_block_size = mem_size;
	g_mem_check_profile.rounds = rounds;

	long actual_mem_size = mem_size;
	int unit_size = sizeof(int);
	if (actual_mem_size % unit_size != 0) {
		long remainder = actual_mem_size % unit_size;
		actual_mem_size += unit_size - remainder;
	}
	g_mem_check_profile.actual_mem_block_size = actual_mem_size;

	g_mem_check_profile.inner_loops = 16;
	g_mem_check_profile.current_mode = 0;
	g_mem_check_profile.current_random = 0;
	g_mem_check_profile.total_write_bytes_low = 0;
	g_mem_check_profile.total_write_bytes_high = 0;
	g_mem_check_profile.error_count = 0;

	return 0;
}

void usage(char *prog_name) {
	printf("usage:\n");
	printf("%s %s <memory_block_size> %s <rounds>\n", prog_name, PARAM_KEY_MEM_SIZE, PARAM_KEY_ROUND);
}


void increase_total_write_bytes(unsigned long bytes) {
	// 一般情况下测试不会导致64位无符号整数溢出，防止碰到奇葩主机内存过于高速，
	// 用high、low两个64位无符号整数保存总写入字节数。
	unsigned long total = g_mem_check_profile.total_write_bytes_low + bytes;
	if (g_mem_check_profile.total_write_bytes_low > total) {
		g_mem_check_profile.total_write_bytes_high++;
		print_logln("increase_total_write_bytes: low part overflow, increase high to %lu.", g_mem_check_profile.total_write_bytes_high);
	}
	g_mem_check_profile.total_write_bytes_low = total;
}

void *init_mem_with_mode(int mode) {
	int unit_size = sizeof(int);

	void *result = malloc(g_mem_check_profile.actual_mem_block_size);
	if (result == NULL) {
		print_logln("init_mem_with_mode: failed to allocate memory for mode %d.", mode);
		return NULL;
	}

	int *content = (int *) result;
	long count = g_mem_check_profile.actual_mem_block_size / unit_size;
	for (long i = 0; i < count; i++) {
		content[i] = mode;
	}
	increase_total_write_bytes(g_mem_check_profile.actual_mem_block_size);

	return result;
}

int check_mem_with_mode(void *source, int mode) {
	int unit_size = sizeof(int);

	int *content = (int *) source;
	long count = g_mem_check_profile.actual_mem_block_size / unit_size;
	for (long i = 0; i < count; i++) {
		if (content[i] != mode) {
			print_logln("check_mem_with_mode: mem[%ld] failed, expected %d, got %d.", i, mode, content[i]);
			return -4;
		}
	}
	return 0;
}

void *make_destination() {
	void *destination = malloc(g_mem_check_profile.actual_mem_block_size);
	if (destination == NULL) {
		print_logln("make_destination: no memory for destination.");
		return NULL;
	}

	return destination;
}

int check_arrays(void *source, void *destination, long size) {
	long check_size = size / sizeof(int);
	int result = memcmp(source, destination, size);
	if (result != 0) {
		int *src_int = (int *) source;
		int *dst_int = (int *) destination;
		for (long i = 0; i < check_size; i++) {
			if (src_int[i] != dst_int[i]) {
				ErrRec *err = malloc(sizeof(ErrRec));
				err->src = src_int[i];
				err->dest = dst_int[i];
				err->index = i;
				err->write_bytes_low = g_mem_check_profile.total_write_bytes_low;
				err->write_bytes_high = g_mem_check_profile.total_write_bytes_high;
				err->mode = g_mem_check_profile.current_mode;
				err->random = g_mem_check_profile.current_random;
				print_logln("check_arrays: ============ found error No. %d at %d, expected %d, got %d, mode=%d, random=%s, bytes written=%lu:%lu. ============",
						g_mem_check_profile.error_count++,
						err->index, err->src, err->dest, err->mode, (err->random == 0 ? "false" : "true"),
						err->write_bytes_high, err->write_bytes_low);

				if (g_error_records_ptr == NULL) {
					g_error_records_ptr = malloc(sizeof(MyList));
					g_error_records_ptr->content = err;
					g_error_records_ptr->next = NULL;
					g_error_records_tail_ptr = g_error_records_ptr;
				} else {
					g_error_records_tail_ptr->next = malloc(sizeof(MyList));
					g_error_records_tail_ptr = g_error_records_tail_ptr->next;
					g_error_records_tail_ptr->content = err;
					g_error_records_tail_ptr->next = NULL;
				}
			}
		}
	}
	return result;
}

int check_with_mode(int mode) {
	char mode_buf[33];
	intToBinStr(mode_buf, mode);
	print_logln("check_with_mode: %s.", mode_buf);

	g_mem_check_profile.current_mode = mode;
	g_mem_check_profile.current_random = 0;

	void *source = init_mem_with_mode(mode);
	if (source == NULL) {
		print_logln("check_with_mode: no memory for source when check with mode %s.", mode_buf);
		return -3;
	}
	print_logln("check_with_mode: initialized source.");

	int checkSourceResult = check_mem_with_mode(source, mode);
	print_logln("check_with_mode: check source result %d.", checkSourceResult);

	void *destination = make_destination();
	if (destination == NULL) {
		print_logln("check_with_mode: no memory for destination when check with mode %s.", mode_buf);
		return -5;
	}

	int loop_result = 0;
	for (int i = 0; i < g_mem_check_profile.inner_loops; i++) {
		memcpy(destination, source, g_mem_check_profile.actual_mem_block_size);
		increase_total_write_bytes(g_mem_check_profile.actual_mem_block_size);
		int result = check_arrays(source, destination, g_mem_check_profile.actual_mem_block_size);
		if (result != 0) {
			loop_result = 1;
		}
	}
	print_logln("check_with_mode: check destination result %s for mode %s.", loop_result == 0 ? "SUCCESS" : "FAIL", mode_buf);

	free(source);
	free(destination);
	return loop_result != 0;
}

void *init_mem_with_random() {
	int unit_size = sizeof(int);

	void *result = malloc(g_mem_check_profile.actual_mem_block_size);
	if (result == NULL) {
		print_logln("init_mem_with_random: failed to allocate memory for random.");
		return NULL;
	}

	int *content = (int *) result;
	long count = g_mem_check_profile.actual_mem_block_size / unit_size;
	int fd = open("/dev/urandom", O_NONBLOCK | O_RDONLY);
	if (fd < 0) {
		for (long i = 0; i < count; i++) {
			content[i] = i % 2 == 0 ? 0x01234567 : 0x89abcdef;
		}
	} else {
		long count = 0;
		while (count < g_mem_check_profile.actual_mem_block_size) {
			count += read(fd, result + count, g_mem_check_profile.actual_mem_block_size - count);
		}
		close(fd);
	}
	increase_total_write_bytes(g_mem_check_profile.actual_mem_block_size);

	return result;
}

int check_with_random() {
	print_logln("check_with_random:");
	g_mem_check_profile.current_mode = 0;
	g_mem_check_profile.current_random = 1;

	void *source = init_mem_with_random();
	if (source == NULL) {
		print_logln("check_with_random: no memory for source when check with random.");
		return -6;
	}
	print_logln("check_with_random: initialized source.");

	void *destination = make_destination();
	if (destination == NULL) {
		print_logln("check_with_random: no memory for destination when check with random.");
		return -7;
	}

	int loop_count = g_mem_check_profile.inner_loops * 16;
	int loop_result = 0;
	for (int i = 0; i < loop_count; i++) {
		memcpy(destination, source, g_mem_check_profile.actual_mem_block_size);
		increase_total_write_bytes(g_mem_check_profile.actual_mem_block_size);
		int result = check_arrays(source, destination, g_mem_check_profile.actual_mem_block_size);
		if (result != 0) {
			loop_result = 1;
		}
	}
	print_logln("check_with_random: check destination result %s for random.", loop_result == 0 ? "SUCCESS" : "FAIL");

	free(source);
	free(destination);
	return loop_result;
}

void dump_and_release_error_records() {
	print_logln("dump_error_records: total write bytes %lu:%lu, total errors: %d.",
			g_mem_check_profile.total_write_bytes_high, g_mem_check_profile.total_write_bytes_low,
			g_mem_check_profile.error_count);

	MyList *p_list = g_error_records_ptr;
	int count = 0;
	while (p_list != NULL) {
		ErrRec *p_err = (ErrRec *) p_list->content;
		print_logln("dump_error_records: error No. %d, position %d, expected %d, got %d, mode=%d, random=%s, bytes written=%lu:%lu.",
				count++,
				p_err->index, p_err->src, p_err->dest, p_err->mode, (p_err->random == 0 ? "false" : "true"),
				p_err->write_bytes_high, p_err->write_bytes_low
				);

		MyList *tmp_list = p_list->next;
		free(p_err);
		free(p_list);
		p_list = tmp_list;
	}

	g_error_records_ptr = NULL;
	g_error_records_tail_ptr = NULL;
}

int check_mem() {
	print_logln("check_mem: ================ start check ================");
	print_logln("check_mem: Memory block size: %ld.", g_mem_check_profile.mem_block_size);
	print_logln("check_mem: Rounds: %d.", g_mem_check_profile.rounds);

	int overall_result = 0;
	int round_result;
	int result;

	struct timeval begin_tv;
	int time_result = gettimeofday(&begin_tv, NULL);
	if (time_result != 0) {
		print_logln("check_mem: can not get start time, %d.", time_result);
	}

	for (int i = 0; i < g_mem_check_profile.rounds; i++) {
		print_logln("check_mem: start round %d.", i);

		round_result = 0;
		result = check_with_mode(0x00000000);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x55555555);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xAAAAAAAA);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x33333333);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xCCCCCCCC);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x0F0F0F0F);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xF0F0F0F0);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x78787878);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x87878787);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x1E1E1E1E);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xE1E1E1E1);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xC3C3C3C3);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x3C3C3C3C);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x00FF00FF);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xFF00FF00);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0x0000FFFF);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xFFFF0000);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_mode(0xFFFFFFFF);
		if (result != 0) {
			round_result = 1;
		}

		result = check_with_random();
		if (result != 0) {
			round_result = 1;
		}
		print_logln("check_mem: result for round %d: %s.", i, round_result == 0 ? "SUCCESS" : "FAIL");

		if (round_result != 0) {
			overall_result = 1;
		}
	}
	print_logln("check_mem: final result: %s.", overall_result == 0 ? "SUCCESS" : "FAIL");
	dump_and_release_error_records();


	return overall_result;
}

int main(int argc, char* argv[]) {
	int result = parse_args(argc, argv);
	if (result != 0) {
		usage(argv[0]);
		return result;
	}

	struct timeval begin_tv;
	int begin_tv_result = gettimeofday(&begin_tv, NULL);

	check_mem();

	struct timeval end_tv;
	int end_tv_result = gettimeofday(&end_tv, NULL);
	if (begin_tv_result == 0 && end_tv_result == 0) {
		unsigned long time_cost = 0;
		time_cost = end_tv.tv_sec - begin_tv.tv_sec;
		time_cost *= 1000000;
		time_cost += end_tv.tv_usec - begin_tv.tv_usec;
		print_logln("================ finished, time cost: %lu us ================", time_cost);
	} else {
		print_logln("================ finished ================");
	}

	if (log_fd > 0) {
		close(log_fd);
	}
	return 0;
}

