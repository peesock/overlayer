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

type TreeInter interface {
	new() TreeInter
	getDir() string
	getData() (string, TreeInter)
	setData(string, TreeInter)
	getEntry(string) (TreeInter, bool)
	setEntry(string, TreeInter)
	setMount(Mount)
}

type TreeSink struct {
	name string
	parent *TreeSink
	entries EntriesSink
	mnt Mount
}
type TreeSource struct {
	name string
	parent *TreeSource
	entries EntriesSource
}
func (*TreeSink) new() TreeInter {
	t := new(TreeSink)
	t.entries = make(EntriesSink)
	return t
}
func (t *TreeSink) getData() (string, TreeInter) { return t.name, t.parent }
func (t *TreeSink) setData(name string, prev TreeInter){
	t.name = name
	t.parent = prev.(*TreeSink)
}
func (t *TreeSink) getEntry(name string) (TreeInter, bool) {
	v, b := t.entries.getEntry(name)
	return v, b
}
func (t *TreeSink) setEntry(name string, next TreeInter){
	if t.entries == nil {
		t.entries = make(EntriesSink)
	}
	t.entries.setEntry(name, next)
}
func (t *TreeSink) setMount(m Mount){ t.mnt = m }

func (*TreeSource) new() TreeInter {
	t := new(TreeSource)
	t.entries = make(EntriesSource)
	return t
}
func (t *TreeSource) getData() (string, TreeInter) { return t.name, t.parent }
func (t *TreeSource) setData(name string, prev TreeInter){
	t.name = name
	t.parent = prev.(*TreeSource)
}
func (t *TreeSource) getEntry(name string) (TreeInter, bool) {
	v, b := t.entries.getEntry(name)
	return v, b
}
func (t *TreeSource) setEntry(name string, next TreeInter){
	if t.entries == nil {
		t.entries = make(EntriesSource)
	}
	t.entries.setEntry(name, next)
}
func (t *TreeSource) setMount(m Mount){}

type EntriesInter interface {
	getEntry(string) (TreeInter, bool)
	getMap() EntriesInter
	setEntry(string, TreeInter)
}

type EntriesSink map[string] *TreeSink
type EntriesSource map[string] *TreeSource
func (e EntriesSink) getEntry(s string) (TreeInter, bool) { v, b := e[s]; return v, b }
func (e EntriesSink) getMap() EntriesInter { return e }
func (e EntriesSink) setEntry(s string, t TreeInter) { e[s] = t.(*TreeSink) }
func (e EntriesSource) getEntry(s string) (TreeInter, bool) { v, b := e[s]; return v, b }
func (e EntriesSource) getMap() EntriesInter { return e }
func (e EntriesSource) setEntry(s string, t TreeInter) { e[s] = t.(*TreeSource) }

type Mount interface {
	mount(string) error
	umount(string) error
	setSource(*TreeSource)
}

type Overlay struct  {
	sourceNode *TreeSource
	keys Keys
	index uint64
}
func (m *Overlay) setSource(t *TreeSource){ m.sourceNode = t }

type Bind struct {
	sourceNode *TreeSource
	recursive bool
}
func (m *Bind) setSource(t *TreeSource){ m.sourceNode = t }

type Keys map[string] string

type RecurseOpts struct {
	bind bool
	overlay bool
}
