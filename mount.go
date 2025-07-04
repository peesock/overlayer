package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Mount struct {
	source string
	sink string
	overlay *Overlay
	bind *Bind
	recurse *RecurseOpts
}

type Keys map[string] string

type Overlay struct  {
	keys Keys
	index uint64
}

type Bind struct {
	recursive bool
}

type RecurseOpts struct {
	bind bool
	overlay bool
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

func umounter(){
	// for _, v := range parseMountinfo() {log(Debug, v)}
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
				continue
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
