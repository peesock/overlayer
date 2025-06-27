package main

import (
	"crypto/sha1"
	"encoding/base64"
	_ "fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Keys map[string] string

func hasCapabilities() bool{
	o, e := unix.PrctlRetInt(unix.PR_CAPBSET_READ, unix.CAP_SYS_ADMIN, 0, 0, 0)
	if o != 1 {
		return false
	}
	if e != nil {
		logErr(e)
		panic(e)
	}
	o, e = unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, unix.CAP_SYS_ADMIN, 0, 0)
	if o != 1 {
		return false
	}
	if e != nil {
		logErr(e)
		panic(e)
	}
	return true
}

func enterNamespace(unshareFlags int){
	logInfo("entering new namespace")
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr {
		Unshareflags: uintptr(unshareFlags),
		UidMappings: []syscall.SysProcIDMap {
			{
				// going with root uid method for now because implementing `unshare -c --keep-caps` looks awful
				ContainerID: 0,
				HostID: syscall.Getuid(),
				Size: 1,
			},
		},
		GidMappings: []syscall.SysProcIDMap {
			{
				ContainerID: 0,
				HostID: syscall.Getuid(),
				Size: 1,
			},
		},
	}
	err := cmd.Start()
	if err != nil {
		logErr(err)
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
	logInfo("next index:", i)

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

	err = os.WriteFile(index + "/" + Names.id, []byte(keyvalues), 0644)
	if err != nil {
		return "", err
	}

	return iStr, nil
}

// ponder single file id
func getIndex(keys Keys) (string, bool) {
	entries, err := os.ReadDir(Config.storage)
	if err != nil {
		logErr(err)
	}

	for _, index := range entries {
		name := index.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, name)
		if ! (matched && index.IsDir()) {
			continue
		}
		if parseId(Config.storage + "/" + name + "/" + Names.id, keys) {
			return name, true
		}
	}

	return "", false
}

func parseId(id string, keys Keys) bool {
	keyvalues, err := os.ReadFile(id)
	if err != nil {
		logErr(err)
		return false
	}
	value := ""
	n := 0
	for i,ii := 0,0; i<len(keyvalues)-1; i++ {
		if keyvalues[i] == '\000' && keyvalues[i+1] == '\n' {
			line := string(keyvalues[ii:i])
			// log("line:", line)
			if n % 2 == 0 { // line is a key
				// log("key")
				value = keys[line]
			} else { // line is a value
				// log("value")
				if value != line {
					// log("value issue")
					return false
				}
			}
			ii=i+2
			i++
			n++
		}
	}

	if n/2 != len(keys) {
		// log("numbah issue", n, len(keys), keys)
		return false
	}

	return true
}

func mount(src, targ, fstype string, flags uintptr, data string) {
	err := syscall.Mount(src, targ, fstype, flags, data)
	if err != nil {
		logErr(err)
		panic("mount failure")
	}
	if fstype != "" {
		Config.mounts = append(Config.mounts, targ)
		logInfo("mounted", fstype, "on", targ)
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
		strings.Join([]string{Config.tree, Names.lower, sink}, "/"),
		// upper
		strings.Join([]string{Config.storage, index, Names.data}, "/"),
		strings.Join([]string{Config.tree, Names.upper, sink}, "/"),
		// overlay
		sink,
		strings.Join([]string{Config.tree, Names.overlay, sink}, "/"),
	}
	for i:=0; i<len(args); i+=2 {
		os.MkdirAll(args[i+1], 0755)
		mount(args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}

	logInfo("tree added")
}

func place(source, sink string, keys Keys) error {
	logInfo("place:", source, sink, keys)
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
		",upperdir=" + indexPath + "/" + Names.data +
		",workdir=" + indexPath + "/" + Names.work +
		"," + Config.overlayOpts
	mount("a", "b", "overlay", 0, data)
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
	out = strings.Join([]string{Config.global, Names.bycwd, out}, "/")
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
			logInfo("made storage", out)
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

var Names = struct{
	program string
	id string
	data string
	work string
	upper string
	lower string
	overlay string
	treeDefault string
	bycwd string
}{
	"overlayer",
	"id",
	"data",
	"work",
	"upper",
	"lower",
	"overlay",
	"tree",
	"by-cwd",
}

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
}

var logInfo = log.New(os.Stderr, Names.program + ": ", 0).Println
var logErr = log.New(os.Stderr, Names.program + "[error]: ", log.Lshortfile).Println

func main(){
	// in the future try to detect who owns the current mount namespace as well
	if (syscall.Getuid() != 0) && ! hasCapabilities() {
		enterNamespace(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS)
		return
	}

	// flag parsing!!!!!!!
	var argKeys = make(Keys)
	for i:=1; i<len(os.Args); i++ {
		flag := os.Args[i]
		switch flag {
		case "-g", "-global":
			Config.global = os.Args[i+1]
			i++
		case "-s", "-storage":
			Config.storage = os.Args[i+1]
			i++
		case "-t", "-tree":
			Config.storage = os.Args[i+1]
			i++
		case "-k", "-key":
			argKeys[os.Args[i+1]] = os.Args[i+2]
			i+=2
		case "--":
			i++
			goto exit
		default:
			b, _ := regexp.MatchString(`^(-p(|lace)|-r(|eplace))(|,[io]{1,2})$`, flag)
			if b {
				var args Place
				if strings.HasPrefix(flag, "-r") {
					args.source = os.Args[i+1]
					args.sink = args.source
					i++
				} else {
					args.source = os.Args[i+1]
					args.sink = os.Args[i+2]
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

	// defaults
	if Config.global == "" {
		xdgDataHome, b := os.LookupEnv("XDG_DATA_HOME")
		if ! b {
			xdgDataHome, b = os.LookupEnv("HOME")
			if ! b {
				logErr("no HOME??????")
				return
			}
			xdgDataHome = xdgDataHome + "/.local/share"
		}
		Config.global = xdgDataHome + "/" + Names.program
	}

	if Config.storage == "" {
		var err error
		Config.storage, err = makeStorage()
		if err != nil {
			logErr(err)
			return
		}
	} else {
		err := os.MkdirAll(Config.storage, 0755)
		if err != nil {
			logErr(err)
			return
		}
	}

	if Config.tree == "" {
		Config.tree = Config.storage + "/" + Names.treeDefault
	}
	err := os.MkdirAll(Config.tree, 0755)
	if err != nil {
		logErr(err)
		return
	}

	if Config.overlayOpts == "" {
		Config.overlayOpts = "userxattr"
	}

	// unmounter
	// for tree, i think it's safe to ignore bind mounts and just lazy umount the parent,
	// but i'm not certain and the granularity here is nice for now.
	defer func(){
		for i:=len(Config.mounts)-1; i>=0; i-- {
			err := syscall.Unmount(Config.mounts[i], 0)
			if err != nil {
				logInfo("mystery umount error.", err, "lazy umounting.")
				err = syscall.Unmount(Config.mounts[i], syscall.MNT_DETACH)
				if err != nil {
					logErr("lazy umount fail???", err)
				}
			}
			logInfo("umounted", Config.mounts[i])
		}
	}()

	if len(Config.place) > 0 {
		// create tree
		mount("tmpfs", Config.tree, "tmpfs", 0, "")
		mount("", Config.tree, "", syscall.MS_SLAVE, "")
		for _, dir := range []string{Names.lower, Names.upper, Names.overlay}{
			err := os.MkdirAll(Config.tree + "/" + dir, 0755)
			if err != nil {
				logErr(err)
				return
			}
		}
		// add overlays
		for _, v := range Config.place {
			place(v.source, v.sink, v.keys)
		}
	}
}
