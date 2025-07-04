package main
// Todo:
// Optimize -key usage, add key append mode
// more advanced flag parsing
// Handle Config.overlay / make the root pivoting optional
// Compile the regex in getIndex
// Fuser for umounter
// Code documentation
// Work on different submounting methods
// Add dedupe?
// put all pivot_rootable functions in a big old object or something idk
// make the Trie (pronounced tree-eh)

/*
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
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
*/
import "C"

// check for and set capabilities with unshare ^

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// mostly for easy renames
const (
	ProgramName = "overlayer"
	IndexId = "id"
	IndexData = "data"
	IndexWork = "work"
	Tree = "tree"
	TreeUpper = "upper"
	TreeLower = "lower"
	TreeOverlay = "overlay"
	RootBase = "root"
	RootNew = "new"
	RootOld = "old"
	Bycwd = "by-cwd"
)

var Pivoting bool

var Config struct {
	global string
	storage string
	tree bool
	treeDir string
	mounts []Mount
	mountpoints []string
	overlayOpts string
	quiet bool
	overlay string
	debug bool
}

func optParse(flag, opt string) bool {
	_, opts, b := strings.Cut(flag, ",")
	if ! b { return false }
	return strings.Contains(opts, opt)
}

func main(){
	// i am NOT making a decorator function
	flagOptsCache := make(map[string]*regexp.Regexp)
	flagOpts := func(flag, opts string, matches... string) bool {
		reg, b := flagOptsCache[matches[0]]
		if ! b {
			pattern := `^(` + strings.Join(matches, "|") + `)(|,[` + opts + `]{1,` + strconv.Itoa(len(opts)) + `})$`
			var err error
			reg, err = regexp.Compile(pattern)
			if err != nil {
				panic(err.Error())
			}
		}
		return reg.MatchString(flag)
	}

	// flag parsing!!!!!!!
	var argKeys = make(Keys)
	var argRecurseOpts *RecurseOpts = nil
	os.Args = os.Args[1:]
	for i:=1; len(os.Args)>0; os.Args = os.Args[i:] {
		i=1
		flag := os.Args[0]
		switch flag {
		case "-d", "-debug":
			Config.debug = true
		case "-q", "-quiet":
			Config.quiet = true
		case "-su":
			Config.overlayOpts = "xino=auto,uuid=auto,metacopy=on"
		case "-t", "-tree":
			Config.tree = true
		case "-T", "-treedir":
			Config.tree = true
			Config.treeDir = os.Args[1]
			i++
		case "-g", "-global":
			Config.global = os.Args[1]
			i++
		case "-s", "-storage":
			Config.storage = os.Args[1]
			i++
		case "-o", "-overlay":
			Config.overlay = os.Args[1]
			i++
		case "-k", "-key":
			argKeys[os.Args[1]] = os.Args[2]
			i+=2
		case "--":
			os.Args = os.Args[i:]
			goto exit

		default:
			switch {
			case flagOpts(flag, "io", "-p", "-place", "-r", "-replace"):
				b, _ := checkDir(os.Args[1], false)
				if ! b {
					return
				}
				var mount Mount
				mount.overlay = new(Overlay)
				mount.source = os.Args[1]
				replace := strings.HasPrefix(flag, "-r")
				if replace {
					mount.sink = mount.source
					i++
				} else {
					mount.sink = os.Args[2]
					i+=2
				}
				if len(argKeys) > 0 {
					mount.overlay.keys = argKeys
					clear(argKeys)
				} else {
					mount.overlay.keys = make(Keys)
					in, out := realpath(mount.source, false), realpath(mount.sink, false)
					if optParse(flag, ""){ // if opts exist
						if optParse(flag, "i"){
							mount.overlay.keys["source"] = in
						}
						if optParse(flag, "o"){
							mount.overlay.keys["sink"] = out
						}
					} else if replace { // defaults for -r
						mount.overlay.keys["source"] = in
						mount.overlay.keys["sink"] = out
					} else { // defaults for -p
						mount.overlay.keys["sink"] = out
					}
				}
				mount.source = realpath(mount.source, true)
				mount.sink = realpath(mount.sink, true)

				if argRecurseOpts != nil {
					mount.recurse = argRecurseOpts
					argRecurseOpts = nil
				}
				Config.mounts = append(Config.mounts, mount)

			case flagOpts(flag, "bo", "-R", "-recurse", "-Recurse"):
				argRecurseOpts = new(RecurseOpts)
				if optParse(flag, ""){
					if optParse(flag, "b") {
						argRecurseOpts.bind = true
					}
					if optParse(flag, "o") {
						argRecurseOpts.overlay = true
					}
				} else {
					argRecurseOpts.bind = true
				}

			default:
				goto exit
			}
		}
	}
	exit:
	var cmd *exec.Cmd
	fi, _ := os.Stdin.Stat()
	if len(os.Args) == 0 {
		if fi.Mode() & os.ModeCharDevice == 0 {
			// not a terminal
			log(Error, "Not in a terminal; must specify command to run.")
			return
		}
		shell, b := os.LookupEnv("SHELL")
		if b {
			cmd = exec.Command(shell)
		} else {
			log(Error, "Could not run $SHELL.")
			return
		}
	} else {
		cmd = exec.Command(os.Args[0], os.Args[1:]...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// defaults
	if Config.global == "" {
		xdgDataHome, b := os.LookupEnv("XDG_DATA_HOME")
		if ! b {
			xdgDataHome, b = os.LookupEnv("HOME")
			if ! b {
				log(Error, "Could not find $HOME.")
				return
			}
			xdgDataHome = xdgDataHome + "/.local/share"
		}
		Config.global = xdgDataHome + "/" + ProgramName
	}

	if Config.storage == "" {
		var err error
		Config.storage, err = setStorage()
		if err != nil {
			log(Error, err)
			return
		}
	} else {
		err := mkdir(Config.storage)
		if err != nil {
			log(Error, err)
			return
		}
	}
	Config.storage = realpath(Config.storage, true)

	if Config.overlayOpts == "" {
		Config.overlayOpts = "userxattr"
	}

	// make and pivot root

	// save cwd for later
	cwd, err := os.Getwd()
	if err != nil {
		log(Error, err)
	}
	base := Config.storage + "/" + RootBase
	err = mkdir(base)
	if err != nil {
		log(Error, err)
		return
	}
	syscall.Mount("tmpfs", base, "tmpfs", 0, "")
	mkdir(base + "/" + RootOld)
	mkdir(base + "/" + RootNew)
	err = syscall.PivotRoot(base, base + "/" + RootOld)
	if err != nil {
		log(Error, err)
		return
	}
	err = syscall.Chdir("/")
	if err != nil {
		log(Error, err)
		return
	}

	Pivoting = true

	// set old root propagation private
	err = syscall.Mount(RootOld, RootOld, "", syscall.MS_PRIVATE|syscall.MS_REC, "")
	if err != nil {
		log(Error, err)
		return
	}
	// mount oldroot to newroot
	syscall.Mount("/" + RootOld, "/" + RootNew, "bind", syscall.MS_BIND|syscall.MS_REC, "")

	// add mounts
	for _, m := range Config.mounts {
		err := m.mount()
		if err != nil {
			log(Error, "Failed to mount:", err)
		}
	}

	// umount /oldroot
	err = syscall.Unmount(RootOld, syscall.MNT_DETACH)
	if err != nil {
		log(Error, err)
		return
	}
	// get fd for current root, to unmount after later pivot
	rootFd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		log(Error, err)
		return
	}
	// cd /newroot
	err = syscall.Chdir("/" + RootNew)
	if err != nil {
		log(Error, err)
		return
	}
	// pivot
	err = syscall.PivotRoot(".", ".")
	if err != nil {
		log(Error, err)
		return
	}
	// umount old root
	err = syscall.Fchdir(rootFd)
	if err != nil {
		log(Error, err)
		return
	}
	err = syscall.Unmount(".", syscall.MNT_DETACH)
	if err != nil {
		log(Error, err)
		return
	}
	err = syscall.Chdir("/")
	if err != nil {
		log(Error, err)
		return
	}

	// due to overlays having potentially any alteration to their original content, the old cwd is not
	// guaranteed to exist anymore.
	err = syscall.Chdir(cwd)
	if err != nil {
		// try HOME
		cwd = os.Getenv("HOME")
		err = syscall.Chdir(cwd)
		if err != nil {
			cwd = "/"
		}
	}

	// all done with overlay setup
	Pivoting = false

	if Config.tree {
		if Config.treeDir == "" {
			Config.treeDir = Config.storage + "/" + Tree
		}
		// make tree
		err := mkdir(Config.treeDir)
		if err != nil {
			log(Error, err)
			return
		}
		syscall.Mount("tmpfs", Config.treeDir, "tmpfs", 0, "")
		syscall.Mount("", Config.treeDir, "", syscall.MS_SLAVE, "")
		for _, dir := range []string{TreeLower, TreeUpper, TreeOverlay}{
			err = mkdir(Config.treeDir + "/" + dir)
			if err != nil {
				log(Error, err)
				return
			}
		}
		for _, p := range Config.mounts {
			treeAdd(p)
		}
	}

	// unmount everything on exit
	defer umounter()

	// execute
	cmd.Run()
	// cmd.ProcessState.ExitCode()
}
