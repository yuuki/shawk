// Code generated by go-bindata. (@generated) DO NOT EDIT.
// sources:
// ../data/schema/flows.sql
package data

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _DataSchemaFlowsSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x93\x4f\x8f\x9b\x30\x10\xc5\xef\x7c\x8a\xb9\x01\x12\x87\x1c\xda\x53\xd4\x95\x28\x99\xb4\x68\x09\x9b\xf2\x47\xda\x9c\x2c\x2f\xb8\xa9\xa5\x0d\x20\xe3\x4d\xfb\xf1\x2b\xff\x21\xac\xbb\x49\x9a\xaa\xcb\x05\x4b\x7e\xf3\xde\x78\xfc\x73\x52\x60\x5c\x21\x54\xbb\x2d\xc2\xf7\xe7\xfe\x27\x69\xb9\x60\x8d\xe4\x7d\x07\x71\x09\x98\xd7\x1b\x08\x7c\xda\x48\x7e\x64\x7e\x04\xfe\x40\xc7\x51\x2d\xc3\xa5\xe7\x4d\xa5\xf1\xe7\x0c\x21\x5d\x43\xfe\x50\x01\x3e\xa6\x65\x55\x42\xd7\xb7\x6c\x84\xc0\x03\x00\xbd\x26\xbc\x85\x27\xbe\x1f\x99\xe0\xf4\x59\x0b\xf3\x3a\xcb\x60\x5b\xa4\x9b\xb8\xd8\xc1\x3d\xee\x22\xad\xe5\xc3\xf1\x83\xfe\x77\x4c\x9e\x64\x66\x6b\xe8\x85\x34\x5b\x92\xed\x99\x98\x4d\x92\xaf\x98\xdc\x43\xa0\xf7\xef\x3e\xc1\x22\xb4\xfa\x3d\x6f\xaf\xea\xd5\xbe\xd6\xc3\x0a\xd7\x71\x9d\x55\xb0\xb0\x95\x1d\x3d\x30\x00\x38\x52\xd1\xfc\xa0\x22\xf8\xb8\x08\xe7\xea\x49\xeb\xfb\x91\xa7\xd5\x75\x9e\x7e\xab\x11\x02\xd5\x7a\xa4\xbb\x8c\x74\x76\x64\x7c\x42\x2f\x5c\x4e\x93\xb2\xd2\x34\x5f\xe1\xe3\xb9\x81\x11\xe5\x41\x94\x05\xd1\xb5\x84\xb7\xbf\xe0\x21\xb7\xd3\xac\xcb\x34\xff\x02\x4f\x52\x30\x76\x39\xed\x94\x75\x39\xe4\x6f\xd6\x37\x1b\x99\x6e\x6f\x6b\xd4\x7a\x5e\x63\x46\xd1\x37\x31\xa3\x49\x34\xf7\xe7\x7c\xb7\x30\x34\x03\xec\x7e\x7f\xd0\xed\xd2\x35\xf6\x2f\xa2\x61\x64\x62\xf5\x75\x20\xef\x66\x14\xa1\xc0\x35\x16\x98\x27\x78\x62\xdc\x96\x84\xea\xfc\x2b\xcc\xb0\x42\x48\xe2\x32\x89\x57\x68\xdb\x61\xa3\xe4\x1d\x55\x99\x8e\xfd\xff\x3b\x37\x7d\xd7\x99\xc3\x8c\xce\x41\x2f\x11\xff\x5a\x7f\x77\x7a\x27\x8d\x60\x54\xb2\xb7\xa3\x96\xfc\xc0\x46\x49\x0f\xc3\x5b\xf6\x93\xba\x28\x30\xaf\x48\x95\x6e\xb0\xac\xe2\xcd\xd6\x38\xbd\x0c\xed\x3b\x38\x39\x8f\xca\xbd\x96\xe8\xdc\x30\xa3\xf9\xc2\x6f\x7c\x6b\x1a\x34\x62\xad\x95\xe3\x4c\xc5\x04\xb2\x61\xd1\x01\xf9\x1f\x5b\xb9\xfa\x7e\x4c\x07\x3a\xda\xda\x5e\xce\x3d\x9b\xe3\x36\x13\x2e\xbd\xdf\x01\x00\x00\xff\xff\xb9\x53\xb1\x33\xc7\x05\x00\x00")

func DataSchemaFlowsSqlBytes() ([]byte, error) {
	return bindataRead(
		_DataSchemaFlowsSql,
		"../data/schema/flows.sql",
	)
}

func DataSchemaFlowsSql() (*asset, error) {
	bytes, err := DataSchemaFlowsSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "../data/schema/flows.sql", size: 1479, mode: os.FileMode(420), modTime: time.Unix(1561700124, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"../data/schema/flows.sql": DataSchemaFlowsSql,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"..": &bintree{nil, map[string]*bintree{
		"data": &bintree{nil, map[string]*bintree{
			"schema": &bintree{nil, map[string]*bintree{
				"flows.sql": &bintree{DataSchemaFlowsSql, map[string]*bintree{}},
			}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
