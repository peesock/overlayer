#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <linux/capability.h>
__attribute__((constructor)) void enter_ns(void) {
	int flags = CLONE_NEWNS;
	if (getuid() != 0) {
		int cap = prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0);
		if (cap != 1){
			flags |= CLONE_NEWUSER;
		} else {
			cap = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, 0, 0);
			if (cap != 1) {
				flags |= CLONE_NEWUSER;
			}
		}
	}
	struct {
		char *file;
		int id;
	} info[2];
	info[0].file = "/proc/self/uid_map";
	info[1].file = "/proc/self/gid_map";
	info[0].id = geteuid();
	info[1].id = getegid();
	unshare(flags);
	FILE *fp;
	fp = fopen("/proc/self/setgroups", "w+");
	fputs("deny", fp);
	fclose(fp);
	for (int i=0; i<2; i++){
		fp = fopen(info[i].file, "w+");
		fprintf(fp, "%d %d 1\n", info[i].id, info[i].id);
		fclose(fp);
	}
}
