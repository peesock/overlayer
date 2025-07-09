#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <unistd.h>
#include <fcntl.h>

int cmp_reg(int fd1, int fd2, size_t bufsize){
	bufsize *= 4;
	char buffer1[bufsize];
	char buffer2[bufsize];
	int n1;
	int n2;
	do {
		n1 = read(fd1, buffer1, bufsize);
		if (n1 < 0){
			return -1;
		}
		n2 = read(fd2, buffer2, bufsize);
		if (n1 != n2){
			return -1;
		}
		if (memcmp(buffer1, buffer2, n1) != 0)
			return 1;
	} while (n1 > 0);
	return 0;
}

#define cleanup() close(fd1); close(fd2)
#define openat2(str, opt) syscall(SYS_openat2, AT_FDCWD, str, opt, sizeof(struct open_how))
extern int cmp(const char *file1, const char *file2){
	int fd1, fd2;
	struct open_how opt = {};
	opt.flags = O_PATH|O_NOFOLLOW;
	fd1 = openat2(file1, &opt);
	if (fd1 < 0){
		return -1;
	}
	fd2 = openat2(file2, &opt);
	if (fd2 < 0){
		close(fd1);
		return -1;
	}
	struct stat stat1, stat2;
	if (fstat(fd1, &stat1) < 0 || fstat(fd2, &stat2) < 0){
		cleanup();
		return -1;
	}
	if (stat1.st_mode != stat2.st_mode){
		cleanup();
		return 1;
	}

	switch (stat1.st_mode & S_IFMT) {

		case S_IFREG:
			if (stat1.st_size != stat2.st_size){
				cleanup();
				return 1;
			}
			cleanup();
			opt.flags = O_RDONLY;
			fd1 = openat2(file1, &opt);
			if (fd1 < 0){
				return -1;
			}
			fd2 = openat2(file2, &opt);
			if (fd2 < 0){
				close(fd1);
				return -1;
			}
			int s = cmp_reg(fd1, fd2, stat1.st_blksize);
			cleanup();
			return s;

		case S_IFLNK:
			if (stat1.st_size != stat2.st_size){
				cleanup();
				return 1;
			}
			// symlink size should be small enough
			char buf1[stat1.st_size];
			char buf2[stat1.st_size];
			if (readlinkat(fd1, "", buf1, stat1.st_size) < 1){
				cleanup();
				return 1;
			}
			if (readlinkat(fd2, "", buf2, stat1.st_size) < 1){
				cleanup();
				return 1;
			}
			if (memcmp(buf1, buf2, stat1.st_size) == 0){
				cleanup();
				return 0;
			}
	}
	cleanup();
	return 2; // special device
}
