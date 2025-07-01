package main
// todo:
// log mkdirs
// test overlayescapeopts
// optimize -key usage
// whether to add tree-only mode
// handle Config.overlay / make the root pivoting optional
// submounter should run in flag parsing to add placements and also binds (make a new Config entry)
// also, make submounter a method.
// compile the regex in getIndex
// change some struct arguments to struct pointers for speed

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	// "time"
)

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
	if (getuid() == 0) return;
	int cap = prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0);
	if (cap == 1){
		cap = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, 0, 0);
		if (cap == 1) {
			return;
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
	unshare(CLONE_NEWUSER|CLONE_NEWNS);
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

const (
	Program = "overlayer"
	Id = "id"
	Data = "data"
	Work = "work"
	Upper = "upper"
	Lower = "lower"
	Overlay = "overlay"
	Tree = "tree"
	RootBase = "chroot"
	RootNew = "new"
	RootOld = "old"
	Bycwd = "by-cwd"
)

type Keys map[string] string

type Place struct  {
	source string
	sink string
	keys Keys
	index uint64
}

type Recurse struct {
	true bool
	bind bool
	overlay bool
}

var Config struct {
	global string
	storage string
	tree bool
	treeDir string
	places []Place
	mounts []string
	overlayOpts string
	quiet bool
	overlay string
	recurse Recurse
}

type LogMode byte
const (
	User LogMode = iota
	Error
	Debug
)

func log(mode LogMode, args... any){
	switch mode {
	case User:
		if Config.quiet {
			return
		}
		fmt.Fprintln(os.Stderr, append([]any{Program + ":"}, args...)...)
	case Debug, Error:
		var msg string
		switch mode {
			case Debug: msg = "DEBUG"
			case Error: msg = "ERROR"
		}
		_, file, line, _ := runtime.Caller(1)
		fmt.Fprintln(os.Stderr, append([]any{
			Program + "[" + msg + "]: " + file + ":" + strconv.Itoa(line) + ":",
		}, args...)...)
	}
}

func makeIndex(index uint64, keys Keys) (error) {
	indexPath := Config.storage + "/" + strconv.FormatUint(index, 10)
	err := os.MkdirAll(indexPath + "/" + Data, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(indexPath + "/" + Work, 0755)
	if err != nil {
		return err
	}

	var keyvalues string = ""
	for k, v := range keys {
		// delimit by null *and* newline for human readability
		keyvalues = keyvalues + k + "\000\n" + v + "\000\n"
	}

	err = os.WriteFile(indexPath + "/" + Id, []byte(keyvalues), 0644)
	if err != nil {
		return err
	}

	return nil
}

func getNextIndex() (uint64, error) {
	// list entries and find lowest possible index to add
	entries, err := os.ReadDir(Config.storage)
	if err != nil {
		return 0, err
	}
	indexMap := make(map[uint64]bool)
	for _, entry := range entries {
		indexString := entry.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, indexString)
		if matched {
			i, err := strconv.ParseUint(indexString, 10, 0)
			if err != nil {
				return 0, err
			}
			indexMap[i] = true
		}
	}
	var i uint64 = 0
	for range indexMap {
		if indexMap[i] {
			i++
			continue
		}
		break
	}
	return i, nil
}

// ponder single file id
func getIndex(keys Keys) (uint64, bool) {
	entries, err := os.ReadDir(Config.storage)
	if err != nil {
		log(Error, err)
	}

	for _, entry := range entries {
		indexString := entry.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, indexString)
		if ! (matched && entry.IsDir()) {
			continue
		}
		if parseId(Config.storage + "/" + indexString + "/" + Id, keys) {
			index, err := strconv.ParseUint(indexString, 10, 64)
			if err != nil {
				log(Error, err)
				return 0, false
			}
			return index, true
		}
	}
	return 0, false
}

func parseId(id string, keys Keys) bool {
	keyvalues, err := os.ReadFile(id)
	if err != nil {
		log(Error, err)
		return false
	}
	value := ""
	n := 0
	for i,ii := 0,0; i<len(keyvalues)-1; i++ {
		if keyvalues[i] == '\000' && keyvalues[i+1] == '\n' {
			line := string(keyvalues[ii:i])
			if n % 2 == 0 { // line is a key
				value = keys[line]
			} else { // line is a value
				if value != line {
					return false
				}
			}
			ii=i+2
			i++
			n++
		}
	}

	if n/2 != len(keys) {
		return false
	}
	return true
}

func umounter(){
	// time.Sleep(time.Second)
	for i:=len(Config.mounts)-1; i>=0; i-- {
		log(User, "Unmounting", Config.mounts[i])
		err := syscall.Unmount(Config.mounts[i], 0)
		if err != nil {
			log(User, "Umount error.", err)
			log(User, "Lazy umounting.")
			err = syscall.Unmount(Config.mounts[i], syscall.MNT_DETACH)
			if err != nil {
				log(Error, "Could not lazily umount.", err)
			}
		}
	}
}

func mount(src, targ, fstype string, flags uintptr, data string) {
	// time.Sleep(time.Millisecond * 100)
	if fstype != "" {
		log(User, "Mounting", fstype, "on", targ)
	}
	err := syscall.Mount(src, targ, fstype, flags, data)
	if err != nil {
		log(Error, "mount arguments:", []any{src, targ, fstype, flags, data})
		panic(err.Error())
	}
}

func escapeOverlayOpts(s string) string {
	in := []byte(s)
	out := make([]byte, 0, len(in))
	for _, v := range in {
		switch v {
		case '\\', ',', ':':
			out = append(out, '\\', v)
		default:
			out = append(out, v)
		}
	}
	return string(out)
}

func submounter(dir string, data *syscall.Stat_t) {
	if data == nil {
		syscall.Lstat(dir, data)
	}
	dev := data.Dev
	entries, err := os.ReadDir(dir)
	if err != nil {
		log(Error, err, dir)
	}
	for _, v := range entries {
		name := filepath.Join(dir, v.Name())
		err := syscall.Lstat(name, data)
		if err != nil {
			log(Error, err, name)
			continue
		}
		if data.Dev != dev {
			log(Debug, "imagine i just mounted", name)
		}
		if v.IsDir() {
			submounter(name, data)
		}
	}
}

func treeAdd(p Place, index uint64) {
	log(User, "Adding tree")
	args := []string{
		// lower
		p.source,
		filepath.Join(Config.treeDir, Lower, p.sink),
		// upper
		filepath.Join(Config.storage, strconv.FormatUint(index, 10), Data),
		filepath.Join(Config.treeDir, Upper, p.sink),
		// overlay
		p.sink,
		filepath.Join(Config.treeDir, Overlay, p.sink),
	}
	for i:=0; i<len(args); i+=2 {
		os.MkdirAll(args[i+1], 0755)
		mount(args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}
}

func (p Place) place() error {
	indexPath := "/" + RootOld + escapeOverlayOpts(Config.storage) + "/" + strconv.FormatUint(p.index, 10)
	source := "/" + RootOld + p.source
	sink := "/" + RootNew + p.sink
	data :=
		"lowerdir=" + escapeOverlayOpts(source) +
		",upperdir=" + indexPath + "/" + Data +
		",workdir=" + indexPath + "/" + Work +
		"," + Config.overlayOpts

	mount(source, sink, "overlay", 0, data)
	Config.mounts = append(Config.mounts, p.sink)
	return nil
}

func makeStorage() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	hash := sha1.Sum([]byte(dir))
	out := base64.RawURLEncoding.EncodeToString(hash[:])
	out = filepath.Join(Config.global, Bycwd, out)
	_, err = os.Stat(out)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(out, 0755)
			if err != nil {
				return "", err
			}
			err = os.WriteFile(out + "/name", []byte(dir), 0644)
			if err != nil {
				return "", err
			}
			log(User, "Created storage:", out)
		} else {
			return "", err // error reading
		}
	}
	return out, nil
}

func optParse(flag, opt string) bool {
	_, opts, b := strings.Cut(flag, ",")
	if ! b { return false }
	return strings.Contains(opts, opt)
}

func realpath(s string, complete bool) string {
	if complete {
		var err error
		s, _ = filepath.EvalSymlinks(s)
		s, err = filepath.Abs(s)
		if err != nil {
			panic(err.Error())
		}
		return s
	}
	// same as `realpath -ms --relative-base=.`
	if filepath.IsLocal(s) {
		return filepath.Clean(s)
	}
	s, err := filepath.Abs(s)
	if err != nil {
		panic(err.Error())
	}
	return s
}

func statCheck(s string) bool {
	_, err := os.Stat(s)
	if err != nil {
		log(User, "'" + s + "' could not be statted:", err)
		return false
	}
	return true
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
	os.Args = os.Args[1:]
	for i:=1; len(os.Args)>0; os.Args = os.Args[i:] {
		i=1
		flag := os.Args[0]
		switch flag {
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
				var args Place
				if ! statCheck(os.Args[1]){
					return
				}
				args.source = os.Args[1]
				replace := strings.HasPrefix(flag, "-r")
				if replace {
					args.sink = args.source
					i++
				} else {
					args.sink = os.Args[2]
					i+=2
				}
				if len(argKeys) > 0 {
					args.keys = argKeys
					clear(argKeys)
				} else {
					args.keys = make(Keys)
					in, out := realpath(args.source, false), realpath(args.sink, false)
					if optParse(flag, ""){ // if opts exist
						if optParse(flag, "i"){
							args.keys["source"] = in
						}
						if optParse(flag, "o"){
							args.keys["sink"] = out
						}
					} else if replace { // defaults for -r
						args.keys["source"] = in
						args.keys["sink"] = out
					} else { // defaults for -p
						args.keys["sink"] = out
					}
				}
				args.source = realpath(args.source, true)
				args.sink = realpath(args.sink, true)
				Config.places = append(Config.places, args)

			case flagOpts(flag, "bo", "-R", "-recurse"):
				Config.recurse.true = true
				if optParse(flag, ""){
					if optParse(flag, "b") {
						Config.recurse.bind = true
					}
					if optParse(flag, "o") {
						Config.recurse.overlay = true
					}
				} else {
					Config.recurse.bind = true
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
		Config.global = xdgDataHome + "/" + Program
	}

	if Config.storage == "" {
		var err error
		Config.storage, err = makeStorage()
		if err != nil {
			log(Error, err)
			return
		}
	} else {
		err := os.MkdirAll(Config.storage, 0755)
		if err != nil {
			log(Error, err)
			return
		}
	}
	Config.storage = realpath(Config.storage, true)

	if Config.overlayOpts == "" {
		Config.overlayOpts = "userxattr"
	}

	// calculate and create indexes
	var err error
	for i := range Config.places {
		p := &(Config.places[i])
		index, b := getIndex(p.keys)
		if ! b {
			index, err = getNextIndex()
			if err != nil {
				log(Error, err)
				return
			}
			log(User, "Creating new index:", index)
			err = makeIndex(index, p.keys)
			if err != nil {
				log(Error, err)
				return
			}
		}
		log(User, "Index", strconv.FormatUint(index, 10) + ":", p.sink)
		p.index = index
	}
	// further setup

	// make and pivot root
	runtime.LockOSThread()
	cwd, err := os.Getwd()
	if err != nil {
		log(Error, err)
	}
	base := Config.storage + "/" + RootBase
	err = os.MkdirAll(base, 0755)
	if err != nil {
		log(Error, err)
		return
	}
	syscall.Mount("tmpfs", base, "tmpfs", 0, "")
	os.Mkdir(base + "/" + RootOld, 0755)
	os.Mkdir(base + "/" + RootNew, 0755)
	// syscall.Mount(base + "/" + RootNew, base + "/" + RootNew, "bind", syscall.MS_BIND|syscall.MS_REC, "")
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
	// set old root propagation private
	err = syscall.Mount(RootOld, RootOld, "", syscall.MS_PRIVATE|syscall.MS_REC, "")
	if err != nil {
		log(Error, err)
		return
	}
	// mount oldroot to newroot
	syscall.Mount("/" + RootOld, "/" + RootNew, "bind", syscall.MS_BIND|syscall.MS_REC, "")
	// add overlays
	for _, p := range Config.places {
		err = p.place()
		if err != nil {
			log(Error, err)
			return
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

	if Config.tree {
		if Config.treeDir == "" {
			Config.treeDir = Config.storage + "/" + Tree
		}
		// make tree
		err := os.MkdirAll(Config.treeDir, 0755)
		if err != nil {
			log(Error, err)
			return
		}
		syscall.Mount("tmpfs", Config.treeDir, "tmpfs", 0, "")
		syscall.Mount("", Config.treeDir, "", syscall.MS_SLAVE, "")
		for _, dir := range []string{Lower, Upper, Overlay}{
			err = os.MkdirAll(Config.treeDir + "/" + dir, 0755)
			if err != nil {
				log(Error, err)
				return
			}
		}
		for _, p := range Config.places {
			treeAdd(p, p.index)
		}
	}

	// unmount everything on exit
	defer umounter()

	// execute
	cmd.Run()
	// cmd.ProcessState.ExitCode()
}
