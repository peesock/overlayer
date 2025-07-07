package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type Mount interface {
	mount() error
	umount() error
}

type Keys map[string] string

type Overlay struct  {
	source string
	sink string
	keys Keys
	index uint64
}

type Bind struct {
	source string
	sink string
	recursive bool
}

type Tree struct {
	entries map[string] *Tree
	mount Mount
}

// requires clean, absolute path
func trieAdd(dir string, mount Mount, root *Tree){
	list := strings.Split(dir, "/")
	if list[1] == "" {
		root.mount = mount
		return
	}
	node := root
	list = list[1:]
	bool := false
	var nextNode *Tree
	for _, base := range list {
		log(Debug, node)
		nextNode, bool = node.entries[base]
		if !bool {
			nextNode = new(Tree)
			nextNode.entries = make(map[string]*Tree)
			node.entries[base] = nextNode
		}
		node = nextNode
	}
	node.mount = mount
}

func mounter (node *Tree, wg *sync.WaitGroup){
	defer wg.Done()
	if node.mount != nil {
		err := node.mount.mount()
		if err != nil {
			log(Error, "Mount error:", err)
			// mount() throws an error only when it's impossible to continue
			return
		}
	}
	for _, v := range node.entries {
		wg.Add(1)
		go mounter(v, wg)
	}
}

func (m Bind) mount() error {
	flags := uintptr(syscall.MS_BIND)
	if m.recursive {
		flags |= syscall.MS_REC
	}
	log(User, "Bind mounting:")
	log(User, m.source, "-->", m.sink)
	err := mount(&m, m.source, m.sink, "bind", flags, "")
	return err
}

func (m Overlay) mount() error {
	var err error
	// check if it's even worth trying
	// if syscall.Mount(wrapRoot(m.source, "old"), wrapRoot(m.sink, "new"), "", syscall.MS_BIND, "") != nil {
	// 	log(User, "Overlay failed, bind mounting...")
	// 	m.overlay = nil
	// 	m.bind = &Bind{recursive: true}
	// 	err = m.mount()
	// 	return err
	// }
	// syscall.Unmount(wrapRoot(m.sink, "new"), 0)

	// get or make index
	index, b := getIndex(m.keys)
	if ! b {
		index, err = getNextIndex()
		if err != nil {
			return err
		}
		log(User, "Creating new index:", index)
		err = makeIndex(index, m.keys)
		if err != nil {
			return err
		}
	}
	m.index = index

	// mount overlay
	indexPath := wrapRoot(escapeOverlayOpts(Config.storage), "old") + "/" + strconv.FormatUint(m.index, 10)
	data :=
	"lowerdir=" + escapeOverlayOpts(wrapRoot(m.source, "old")) +
	",upperdir=" + indexPath + "/" + IndexData +
	",workdir=" + indexPath + "/" + IndexWork +
	"," + Config.overlayOpts
	log(User, "Mounting overlayfs [index " + strconv.FormatUint(index, 10) + "]:")
	log(User, m.source, "-->", m.sink)
	err = mount(&m, m.source, m.sink, "overlay", 0, data)
	return err
}

type RecurseOpts struct {
	bind bool
	overlay bool
}

func mount(node Mount, source, sink, fstype string, flags uintptr, data string) error {
	realSource := wrapRoot(source, "old")
	realSink := wrapRoot(sink, "new")
	// note for the future: this method makes it impossible to put mounts on top of each other (without multiple overlayer calls).
	err := syscall.Mount(realSource, realSink, fstype, flags, data)
	if err != nil {
		node = nil
	}
	return err
}

func (m Overlay) umount() error {
	log(User, "Unmounting", m.sink)
	err := syscall.Unmount(m.sink, 0)
	if err != nil {
		log(User, "Unmount:", err, "—", "lazy unmounting...")
		err = syscall.Unmount(m.sink, syscall.MNT_DETACH)
	}
	return err
}

func (m Bind) umount() error {
	log(User, "Unmounting", m.sink)
	err := syscall.Unmount(m.sink, syscall.MNT_DETACH)
	return err
}

func umounter(node *Tree, wg *sync.WaitGroup){
	defer wg.Done()
	var wg2 sync.WaitGroup
	for _, v := range node.entries {
		wg2.Add(1)
		go umounter(v, &wg2)
	}
	wg2.Wait()
	if node.mount != nil {
		err := node.mount.umount()
		if err != nil {
			log(Error, "Failed to unmount.")
		}
	}
}

func submounter(dir string, opts RecurseOpts, node *Tree){
	// chosen function (there will be options later on)
	list := getSubmounts(dir)
	for _, v := range list {
		log(Debug, v)
		addSubmount(v, opts, node)
	}
}

func getSubmounts(dir string) []string {
	list := parseMountinfo()
	out := make([]string, 0)
	for _, mountpoint := range list {
		if strings.HasPrefix(mountpoint, dir) && mountpoint != dir {
			_, err := checkDir(mountpoint, true)
			if err != nil {
				log(User, "Mount point", mountpoint, "no longer exists")
				log(Debug, err)
				continue
			}
			out = append(out, mountpoint)
		}
	}
	return out
}

// wraps mount objects to make them submounts
func addSubmount(dir string, opts RecurseOpts, node *Tree) {
	// *only* the user-specified parent should have recurse, not submounts
	switch {
	case opts.overlay:
		mount := Overlay{
			source: dir,
			sink: dir,
			keys: make(Keys),
		}
		mount.keys["source"] = mount.source
		mount.keys["sink"] = mount.sink
		// for now we probably want to differentiate between user-specified and automatic mounts like these
		mount.keys["submount"] = "true"
		trieAdd(dir, mount, node)
	case opts.bind:
		mount := Bind{
			source: dir,
			sink: dir,
			recursive: false,
		}
		trieAdd(dir, mount, node)
	}
}

func (m Overlay) dbgTreeAdd() {
	log(User, "Adding tree")
	args := []string{
		// lower
		m.source,
		filepath.Join(Config.treeDir, DbgTreeLower, m.sink),
		// upper
		filepath.Join(Config.storage, strconv.FormatUint(m.index, 10), IndexData),
		filepath.Join(Config.treeDir, DbgTreeUpper, m.sink),
		// overlay
		m.sink,
		filepath.Join(Config.treeDir, DbgTreeOverlay, m.sink),
	}
	for i:=0; i<len(args); i+=2 {
		mkdir(args[i+1])
		mount(nil, args[i], args[i+1], "bind", syscall.MS_BIND, "")
	}
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
