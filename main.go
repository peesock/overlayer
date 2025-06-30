package main
// todo
// log mkdirs
// test overlayescapeopts
// whether to add tree-only mode

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
	Bycwd = "by-cwd"
)

type Keys map[string] string

type Place struct  {
	source string
	sink string
	keys Keys
}

var Config struct {
	global string
	storage string
	tree bool
	treeDir string
	place []Place
	mounts []string
	overlayOpts string
	quiet bool
	relative string
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

func makeNextIndex(keys Keys) (string, error) {
	// list entries and find lowest possible index to add
	entries, err := os.ReadDir(Config.storage)
	if err != nil {
		return "", err
	}
	indexMap := make(map[uint64]bool)
	for _, index := range entries {
		name := index.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, name)
		if matched {
			i, err := strconv.ParseUint(name, 10, 0)
			if err != nil {
				return "", err
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
	log(User, "Next index:", i)

	// create index
	iStr := strconv.FormatUint(i, 10)
	index := Config.storage + "/" + iStr
	err = os.MkdirAll(index + "/data", 0755)
	if err != nil {
		return "", err
	}
	err = os.MkdirAll(index + "/work", 0755)
	if err != nil {
		return "", err
	}

	var keyvalues string = ""
	for k, v := range keys {
		// delimit by null *and* newline for human readability
		keyvalues = keyvalues + k + "\000\n" + v + "\000\n"
	}

	err = os.WriteFile(index + "/" + Id, []byte(keyvalues), 0644)
	if err != nil {
		return "", err
	}

	return iStr, nil
}

// ponder single file id
func getIndex(keys Keys) (string, bool) {
	entries, err := os.ReadDir(Config.storage)
	if err != nil {
		log(Error, err)
	}

	for _, index := range entries {
		name := index.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, name)
		if ! (matched && index.IsDir()) {
			continue
		}
		if parseId(Config.storage + "/" + name + "/" + Id, keys) {
			return name, true
		}
	}

	return "", false
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

func mount(src, targ, fstype string, flags uintptr, data string) {
	// time.Sleep(time.Millisecond * 100)
	err := syscall.Mount(src, targ, fstype, flags, data)
	if err != nil {
		panic(err.Error())
	}
	if fstype != "" {
		Config.mounts = append(Config.mounts, targ)
		log(User, "Mounted", fstype, "on", targ)
	}
}

func escapeOverlayOpts(s string) string {
	in := []byte(s)
	var out []byte
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

func treeAdd(source, sink, index string) {
	if ! Config.tree {
		return
	}
	log(User, "Adding tree")
	args := []string{
		// lower
		source,
		filepath.Join(Config.treeDir, Lower, sink),
		// upper
		filepath.Join(Config.storage, index, Data),
		filepath.Join(Config.treeDir, Upper, sink),
		// overlay
		sink,
		filepath.Join(Config.treeDir, Overlay, sink),
	}
	for i:=0; i<len(args); i+=2 {
		os.MkdirAll(args[i+1], 0755)
		mount(args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}
}

func treeCreate() error {
	if ! Config.tree {
		return nil
	}
	err := os.MkdirAll(Config.treeDir, 0755)
	if err != nil {
		return err
	}
	mount("tmpfs", Config.treeDir, "tmpfs", 0, "")
	mount("", Config.treeDir, "", syscall.MS_SLAVE, "")
	for _, dir := range []string{Lower, Upper, Overlay}{
		err = os.MkdirAll(Config.treeDir + "/" + dir, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p Place) place() error {
	var err error
	index, success := getIndex(p.keys)
	if ! success {
		index, err = makeNextIndex(p.keys)
		if err != nil {
			return err
		}
	}
	indexPath := escapeOverlayOpts(Config.storage) + "/" + index
	data :=
		"lowerdir=" + escapeOverlayOpts(p.source) +
		",upperdir=" + indexPath + "/" + Data +
		",workdir=" + indexPath + "/" + Work +
		"," + Config.overlayOpts
	mount(p.source, filepath.Join(Config.relative, p.sink), "overlay", 0, data)
	treeAdd(p.source, p.sink, index)
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

func ioParse(args Place, flag string) Keys {
	IN := false
	OUT := false
	out := make(Keys)
	if i := strings.IndexByte(flag, ','); i < 0 {
		if args.sink == args.source { // defaults
			IN, OUT = true, true
		} else {
			OUT = true
		}
	} else {
		s := flag[i+1:]
		if strings.Contains(s, "i") {
			IN = true
		}
		if strings.Contains(s, "o") {
			OUT = true
		}
	}
	if IN {
		out["source"] = args.source
	}
	if OUT {
		out["sink"] = args.sink
	}
	return out
}

func realpath(s string) string {
	// we don't care about symlinks
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

func main(){
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
		case "-R", "-relative":
			_, err := os.Stat(os.Args[1])
			if err != nil {
				log(User, "Relative dir '" + os.Args[1] + "' could not be statted.")
				return
			}
			Config.relative = os.Args[1]
			i++
		case "-k", "-key":
			argKeys[os.Args[1]] = os.Args[2]
			i+=2
		case "--":
			os.Args = os.Args[i:]
			goto exit
		default:
			b, _ := regexp.MatchString(`^(-p(|lace)|-r(|eplace))(|,[io]{1,2})$`, flag)
			if b {
				var args Place
				_, err := os.Stat(os.Args[1])
				if err != nil {
					log(User, "Source dir '" + os.Args[1] + "' could not be statted.")
					return
				}
				args.source = realpath(os.Args[1])
				if strings.HasPrefix(flag, "-r") {
					args.sink = args.source
					i++
				} else {
					args.sink = realpath(os.Args[2])
					i+=2
				}
				if len(argKeys) > 0 {
					args.keys = argKeys
					clear(argKeys)
				} else {
					args.keys = ioParse(args, flag)
				}
				Config.place = append(Config.place, args)
				continue
			}
			goto exit
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

	if Config.tree && Config.treeDir == "" {
		Config.treeDir = Config.storage + "/" + Tree
	}
	if Config.overlayOpts == "" {
		Config.overlayOpts = "userxattr"
	}

	// unmounter
	// for tree, i think it's safe to ignore bind mounts and just lazy umount the parent,
	// but i'm not certain and the granularity here is nice for now.
	defer func(){
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
	}()

	// create tree
	err := treeCreate()
	if err != nil {
		log(Error, err)
		return
	}
	// add overlays
	for _, v := range Config.place {
		err = v.place()
		if err != nil {
			log(Error, err)
			return
		}
	}
	// execute
	ch := make(chan bool)
	go func(){
		defer func(){
			ch <- true
		}()
		runtime.LockOSThread()
		err := syscall.Unshare(syscall.CLONE_NEWNS)
		if err != nil {
			log(Error, err)
		}
		// in case cwd was mounted over
		cwd, err := os.Getwd()
		if err != nil {
			log(Error, err)
		}
		os.Chdir(cwd)
		if err != nil {
			log(Error, err)
		}
		cmd.Run()
	}()
	<- ch
	// cmd.ProcessState.ExitCode()
}
