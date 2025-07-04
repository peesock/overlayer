package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

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
