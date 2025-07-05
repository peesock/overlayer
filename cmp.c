#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int fd1;
int fd2;
int cleanup(int status){
	close(fd1);
	close(fd2);
	return status;
}

int cmp_reg(int fd1, int fd2, size_t bufsize){
	bufsize *= 4;
	char buffer1[bufsize];
	char buffer2[bufsize];
	int n1;
	int n2;
	do {
		n1 = read(fd1, buffer1, bufsize);
		if (n1 < 0)
			return 1;
		n2 = read(fd2, buffer2, bufsize);
		if (n1 != n2)
			return 1;
		if (memcmp(buffer1, buffer2, n1) != 0)
			return 1;
	} while (n1 > 0);
	return 0;
}

int cmp(const char *file1, const char *file2){
	fd1 = open(file1, O_RDONLY|O_NOFOLLOW);
	if (fd1 == -1){
		close(fd1);
		return 1;
	}
	fd2 = open(file2, O_RDONLY|O_NOFOLLOW);
	if (fd2 == -1)
		return cleanup(1);
	struct stat stat1;
	struct stat stat2;
	if (fstat(fd1, &stat1) == -1)
		return cleanup(1);
	if (fstat(fd2, &stat2) == -1)
		return cleanup(1);
	if (stat1.st_mode != stat2.st_mode)
		return cleanup(1);
	switch (stat1.st_mode & S_IFMT) {
		case S_IFREG:
			if (stat1.st_size != stat2.st_size)
				return cleanup(1);
			return cleanup(cmp_reg(fd1, fd2, stat1.st_blksize));
	}
	return cleanup(1);
}

// int main(int argc, char **argv){
// 	return cmp(argv[1], argv[2]);
// }
