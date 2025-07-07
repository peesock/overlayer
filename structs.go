package main

// mostly for easy renames
const (
	ProgramName = "overlayer"
	IndexId = "id"
	IndexData = "data"
	IndexWork = "work"
	DbgTree = "tree"
	DbgTreeUpper = "upper"
	DbgTreeLower = "lower"
	DbgTreeOverlay = "overlay"
	PivotBase = "pivot"
	PivotNew = "new"
	PivotOld = "old"
	GlobalCwd = "by-cwd"
)

var Config struct {
	global string
	storage string
	tree bool
	treeDir string
	overlayOpts string
	quiet bool
	overlay string
	debug bool
}

type Tree struct {
	entries map[string] *Tree
	mount Mount
}

type Mount interface {
	mount() error
	umount() error
}

type Overlay struct  {
	source string
	sink string
	keys Keys
	index uint64
}

type Keys map[string] string

type Bind struct {
	source string
	sink string
	recursive bool
}
