package core

import (
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// IsSkippableDir Checks if the path is excluded
func IsSkippableDir(excludedPaths []string, path, baseDir string) bool {
	for _, skippablePathIndicator := range excludedPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
			log.Debugf("Path %s is skippable", path)
			return true
		}
		if strings.Contains(path, skippablePathIndicator) || strings.Contains(path, filepath.Join(baseDir, skippablePathIndicator)) {
			log.Debugf("Path %s is skippable", path)
			return true
		}
	}

	log.Debugf("Path %s is not skippable", path)
	return false
}

// IsSkippableFileExtension Checks if the file extension is excluded
func IsSkippableFileExtension(excludedExtensions []string, path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, skippableExt := range excludedExtensions {
		if extension == skippableExt {
			return true
		}
		// special check of .so
		if skippableExt == ".so" {
			if IsSharedLibrary(path) {
				return true
			}
		}
	}
	return false
}

// UpdateDirsPermissionsRW Update permissions for dirs in container images, so that they can be properly deleted
func UpdateDirsPermissionsRW(dir string) error {
	return filepath.WalkDir(dir, func(path string, f os.DirEntry, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				log.Errorf("Error updating permissions for dir %s: %s", path, err)
			}
		}
		return nil
	})
}

// IsSharedLibrary Checks if the file is a shared library
func IsSharedLibrary(path string) bool {
	if path == "" {
		return false
	}

	if strings.HasSuffix(path, ".so") {
		return true
	}

	// check if the file is a shared library
	// it could .so, .so.1, .so.1.2.3
	// https://en.wikipedia.org/wiki/Shared_library
	// below wouldn't work for .so.1.2.3
	// extension := strings.ToLower(filepath.Ext(path))
	filename := filepath.Base(path)
	splitExt := strings.Split(filename, ".")
	if len(splitExt) > 1 {
		if splitExt[1] == "so" {
			return true
		}
	}

	return false
}
