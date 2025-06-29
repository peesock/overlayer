package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
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
	TreeDefault = "tree"
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
	tree string
	place []Place
	mounts []string
	overlayOpts string
	quiet bool
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
	args := []string{
		// lower
		source,
		strings.Join([]string{Config.tree, Lower, sink}, "/"),
		// upper
		strings.Join([]string{Config.storage, index, Data}, "/"),
		strings.Join([]string{Config.tree, Upper, sink}, "/"),
		// overlay
		sink,
		strings.Join([]string{Config.tree, Overlay, sink}, "/"),
	}
	for i:=0; i<len(args); i+=2 {
		os.MkdirAll(args[i+1], 0755)
		mount(args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}

	log(User, "Tree added")
}

func place(source, sink string, keys Keys) error {
	var err error
	index, success := getIndex(keys)
	if ! success {
		index, err = makeNextIndex(keys)
		if err != nil {
			return err
		}
	}

	indexPath := escapeOverlayOpts(Config.storage) + "/" + index
	data :=
		"lowerdir=" + escapeOverlayOpts(source) +
		",upperdir=" + indexPath + "/" + Data +
		",workdir=" + indexPath + "/" + Work +
		"," + Config.overlayOpts
	mount(source, sink, "overlay", 0, data)
	treeAdd(source, sink, index)

	return nil
}

func makeStorage() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	hash := sha1.Sum([]byte(dir))
	out := base64.RawURLEncoding.EncodeToString(hash[:])
	out = strings.Join([]string{Config.global, Bycwd, out}, "/")
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
	type opts uint8
	const (
		IN opts = 1 << iota
		OUT
	)
	var o opts
	out := make(Keys)
	i := strings.IndexByte(flag, ',')
	if i < 0 {
		if args.sink == args.source { // defaults
			o = IN | OUT
		} else {
			o = OUT
		}
	} else {
		s := flag[i+1:]
		if strings.Contains(s, "i") {
			o |= IN
		}
		if strings.Contains(s, "o") {
			o |= OUT
		}
	}
	if o & IN == IN {
		out["source"] = args.source
	}
	if o & OUT == OUT {
		out["sink"] = args.sink
	}
	return out
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
		case "-g", "-global":
			Config.global = os.Args[1]
			i++
		case "-s", "-storage":
			Config.storage = os.Args[1]
			i++
		case "-t", "-tree":
			Config.storage = os.Args[1]
			i++
		case "-k", "-key":
			argKeys[os.Args[1]] = os.Args[2]
			i+=2
		case "--":
			i++
			goto exit
		default:
			b, _ := regexp.MatchString(`^(-p(|lace)|-r(|eplace))(|,[io]{1,2})$`, flag)
			if b {
				var args Place
				if strings.HasPrefix(flag, "-r") {
					args.source = os.Args[1]
					args.sink = args.source
					i++
				} else {
					args.source = os.Args[1]
					args.sink = os.Args[2]
					i+=2
				}
				if len(argKeys) > 0 {
					args.keys = argKeys
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

	if Config.tree == "" {
		Config.tree = Config.storage + "/" + TreeDefault
	}
	err := os.MkdirAll(Config.tree, 0755)
	if err != nil {
		log(Error, err)
		return
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
				log(User, "Umount error.", err, "Lazy umounting.")
				err = syscall.Unmount(Config.mounts[i], syscall.MNT_DETACH)
				if err != nil {
					log(Error, "Could not lazily umount.", err)
				}
			}
		}
	}()

	if len(Config.place) > 0 {
		// create tree
		mount("tmpfs", Config.tree, "tmpfs", 0, "")
		mount("", Config.tree, "", syscall.MS_SLAVE, "")
		for _, dir := range []string{Lower, Upper, Overlay}{
			err := os.MkdirAll(Config.tree + "/" + dir, 0755)
			if err != nil {
				log(Error, err)
				return
			}
		}
		// add overlays
		for _, v := range Config.place {
			place(v.source, v.sink, v.keys)
		}
		// execute
		err := cmd.Run()
		if err != nil {
			log(Error, err)
		}
	}
}
