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
// make the Trie (pronounced tree-eh)

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

type Path string

type Keys map[string] string

type RecurseOpts struct {
	bind bool
	overlay bool
}

type Mount struct {
	source string
	sink string
	overlay *Overlay
	bind *Bind
	recurse *RecurseOpts
}

type Overlay struct  {
	keys Keys
	index uint64
}

type Bind struct {
	recursive bool
}

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
		fmt.Fprintln(os.Stderr, append([]any{ProgramName + ":"}, args...)...)
	case Debug, Error:
		var msg string
		switch mode {
			case Debug:
				if ! Config.debug {
					return
				}
				msg = "DEBUG"
			case Error:
				msg = "ERROR"
		}
		_, file, line, _ := runtime.Caller(1)
		fmt.Fprintln(os.Stderr, append([]any{
			ProgramName + "[" + msg + "]: " + file + ":" + strconv.Itoa(line) + ":",
		}, args...)...)
	}
}

func makeIndex(index uint64, keys Keys) (error) {
	indexPath := wrapRoot(Config.storage, "old") + "/" + strconv.FormatUint(index, 10)
	err := mkdir(indexPath + "/" + IndexData)
	if err != nil {
		return err
	}
	err = mkdir(indexPath + "/" + IndexWork)
	if err != nil {
		return err
	}

	var keyvalues string = ""
	for k, v := range keys {
		// delimit by null *and* newline for human readability
		keyvalues = keyvalues + k + "\000\n" + v + "\000\n"
	}

	err = os.WriteFile(indexPath + "/" + IndexId, []byte(keyvalues), 0644)
	if err != nil {
		return err
	}

	return nil
}

func getNextIndex() (uint64, error) {
	// list entries and find lowest possible index to add
	entries, err := os.ReadDir(wrapRoot(Config.storage, "old"))
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
	entries, err := os.ReadDir(wrapRoot(Config.storage, "old"))
	if err != nil {
		log(Error, err)
	}

	for _, entry := range entries {
		indexString := entry.Name()
		matched, _ := regexp.MatchString(`^[0-9]+$`, indexString)
		if ! (matched && entry.IsDir()) {
			continue
		}
		if parseId(wrapRoot(Config.storage, "old") + "/" + indexString + "/" + IndexId, keys) {
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
	for i:=len(Config.mountpoints)-1; i>=0; i-- {
		mount := wrapRoot(Config.mountpoints[i], "new")
		log(User, "Unmounting", mount)
		err := syscall.Unmount(mount, 0)
		if err != nil {
			log(User, "Unmount:", err, "—", "lazy unmounting...")
			err = syscall.Unmount(mount, syscall.MNT_DETACH)
			if err != nil {
				log(Error, "Could not lazy unmount:", err)
			}
		}
	}
}

func mount(source, sink, fstype string, flags uintptr, data string) error {
	realSource := wrapRoot(source, "old")
	realSink := wrapRoot(sink, "new")
	// note for the future: this method makes it impossible to put mounts on top of each other (without multiple overlayer calls).
	err := syscall.Mount(realSource, realSink, fstype, flags, data)
	if err == nil {
		Config.mountpoints = append(Config.mountpoints, sink)
	}
	return err
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

// func recurseFiles(dir string, data *syscall.Stat_t, opts *RecurseOpts) {
// 	if data == nil {
// 		data = new(syscall.Stat_t)
// 		syscall.Lstat(dir, data)
// 	}
// 	entries, err := os.ReadDir(dir)
// 	if err != nil {
// 		log(Error, err, dir)
// 	}
// 	currentDev := data.Dev
// 	for _, v := range entries {
// 		name := dir + "/" + v.Name()
// 		err := syscall.Lstat(name, data)
// 		if err != nil {
// 			log(Error, err, name)
// 			continue
// 		}
// 		if data.Dev != currentDev {
// 			addSubmount(name, opts)
// 			switch {
// 			// case opts.overlay:
// 			case opts.bind:
// 				continue
// 			}
// 		}
// 		if v.IsDir() {
// 			recurseFiles(name, data, opts)
// 		}
// 	}
// }

func parseMountinfo() []string {
	bytes, err := os.ReadFile(wrapRoot("/proc/self/mountinfo", "new"))
	if err != nil {
		panic(err.Error())
	}
	entries := make([][]byte, 0, 20)
	lineRead:
	var i int;
	for n:=0; n<4; i++ {
		if bytes[i] == ' ' {
			n++
		}
	}
	var j = i+1
	for bytes[j] != ' ' {
		j++
	}
	entries = append(entries, bytes[i:j])
	bytes = bytes[j+1:]
	for i := range bytes {
		if bytes[i] == '\n' {
			bytes = bytes[i+1:]
			if len(bytes) != 0 {
				goto lineRead
			}
		}
	}
	out := make([]string, len(entries))
	for line, entry := range entries {
		for i=0; i<len(entry); i++ {
			if entry[i] == '\\' {
				char, _ := strconv.ParseUint(string(entry[i+1:i+4]), 8, 8)
				entry[i] = byte(char)
				entry = append(entry[:i+1], entry[i+4:]...)
			}
		}
		out[line] = string(entry)
	}
	return out
}
// for _, v := range list {log(Debug, v)}

func submounter(m Mount){
	// chosen function (there will be options later on)
	recurseMounts(m)
}

func recurseMounts(m Mount) {
	// assume the list is sorted by dir depth for now
	list := parseMountinfo()
	realSink := wrapRoot(m.sink, "new")
	for _, mountpoint := range list {
		if strings.HasPrefix(mountpoint, realSink) && mountpoint != realSink {
			b, err := checkDir(mountpoint, true)
			if err != nil {
				log(Debug, err)
			}
			if ! b {
				log(User, "Mount point", mountpoint, "no longer a directory")
				return
			}
			m.sink = unwrapRoot(mountpoint, "new")
			m.source = m.sink // this is basically an opinion
			submount(m)
			// if m.recurse.bind {
			// 	return // we have GOT to make the tree for this to work
			// }
		}
	}
}

// wraps mount objects to make them submounts
func submount(m Mount) error {
	recurseOpts := m.recurse
	// *only* the user-specified parent should have recurse, not submounts
	m.recurse = nil
	switch {
	case recurseOpts.overlay:
		m.bind = nil
		m.overlay = new(Overlay)
		keys := make(Keys)
		keys["source"] = m.source
		keys["sink"] = m.sink
		// for now we probably want to differentiate between user-specified and automatic mounts like these
		keys["submount"] = "true"
		m.overlay.keys = keys
	case recurseOpts.bind:
		m.overlay = nil
		m.bind = new(Bind)
		m.bind.recursive = false
	}
	return m.mount()
}

func treeAdd(m Mount) {
	if m.overlay == nil {
		return // maybe put binds later
	}
	log(User, "Adding tree")
	args := []string{
		// lower
		m.source,
		filepath.Join(Config.treeDir, TreeLower, m.sink),
		// upper
		filepath.Join(Config.storage, strconv.FormatUint(m.overlay.index, 10), IndexData),
		filepath.Join(Config.treeDir, TreeUpper, m.sink),
		// overlay
		m.sink,
		filepath.Join(Config.treeDir, TreeOverlay, m.sink),
	}
	for i:=0; i<len(args); i+=2 {
		mkdir(args[i+1])
		mount(args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}
}

func unwrapRoot(s, oldornew string) string {
	if Pivoting {
		switch oldornew[0] {
		case 'o':
			s, _ = strings.CutPrefix(s, "/" + RootOld)
		case 'n':
			s, _ = strings.CutPrefix(s, "/" + RootNew)
		}
	}
	return s
}

func wrapRoot(s, oldornew string) string {
	if Pivoting {
		switch oldornew[0] {
		case 'o':
			return filepath.Join("/", RootOld, s)
		case 'n':
			return filepath.Join("/", RootNew, s)
		}
	}
	return s
}

func (m Mount) mount() error {
	var err error

	switch {
	case m.overlay != nil: // overlay mount
		// check if it's even worth trying
		if syscall.Mount(wrapRoot(m.source, "old"), wrapRoot(m.sink, "new"), "", syscall.MS_BIND, "") != nil {
			log(User, "Overlay failed, bind mounting...")
			m.overlay = nil
			m.bind = &Bind{recursive: true}
			err = m.mount()
			return err
		}
		syscall.Unmount(wrapRoot(m.sink, "new"), 0)

		// get or make index
		index, b := getIndex(m.overlay.keys)
		if ! b {
			index, err = getNextIndex()
			if err != nil {
				return err
			}
			log(User, "Creating new index:", index)
			err = makeIndex(index, m.overlay.keys)
			if err != nil {
				return err
			}
		}
		m.overlay.index = index

		// mount overlay
		indexPath := wrapRoot(escapeOverlayOpts(Config.storage), "old") + "/" + strconv.FormatUint(m.overlay.index, 10)
		data :=
		"lowerdir=" + escapeOverlayOpts(wrapRoot(m.source, "old")) +
		",upperdir=" + indexPath + "/" + IndexData +
		",workdir=" + indexPath + "/" + IndexWork +
		"," + Config.overlayOpts
		log(User, "Mounting overlayfs [index " + strconv.FormatUint(index, 10) + "]:")
		log(User, m.source, "-->", m.sink)
		err = mount(m.source, m.sink, "overlay", 0, data)
		if err != nil {
			// log(User, "Overlay failed, bind mounting...")
			// m.overlay = nil
			// m.bind = &Bind{recursive: false}
			// err = m.mount()
		} else {
			if m.recurse != nil {
				submounter(m)
			}
		}
		return err

	case m.bind != nil: // bind mount
		flags := uintptr(syscall.MS_BIND)
		if m.bind.recursive {
			flags |= syscall.MS_REC
		}
		log(User, "Bind mounting:")
		log(User, m.source, "-->", m.sink)
		err = mount(m.source, m.sink, "bind", flags, "")
		if err != nil {
			if ! m.bind.recursive {
				log(User, "Bind mount failed, trying recursive...")
				m.bind.recursive = true
				err = m.mount()
				return err
			}
		}
		if m.recurse != nil {
			submounter(m)
		}
		return err
	default:
		return nil
	}
}

func setStorage() (string, error) {
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
			log(User, "Creating new storage:", out)
			err = mkdir(out)
			if err != nil {
				return "", err
			}
			err = os.WriteFile(out + "/name", []byte(dir), 0644)
			if err != nil {
				return "", err
			}
		} else {
			return "", err // error reading
		}
	} else {
		log(User, "Storage:", out)
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

func checkDir(dir string, quiet bool) (bool, error) {
	s, err := os.Stat(dir)
	if err != nil {
		if ! quiet {
			log(User, "'" + dir + "' could not be statted:", err)
		}
		return false, err
	}
	if s.IsDir() {
		return true, nil
	}
	return false, nil
}

func mkdir(dir string) error {
	b, _ := checkDir(dir, true)
	if ! b {
		log(Debug, "Creating", dir)
		return os.MkdirAll(dir, 0755)
	}
	return nil
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
