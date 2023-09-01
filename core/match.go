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
			return true
		}
		if strings.Contains(path, skippablePathIndicator) || strings.Contains(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
	}

	return false
}

// IsSkippableFileExtension Checks if the file extension is excluded
func IsSkippableFileExtension(excludedExtensions []string, path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, skippableExt := range excludedExtensions {
		if extension == skippableExt {
			return true
		}
	}
	return false
}

// UpdateDirsPermissionsRW Update permissions for dirs in container images, so that they can be properly deleted
func UpdateDirsPermissionsRW(dir string) {
	filepath.WalkDir(dir, func(path string, f os.DirEntry, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				log.Errorf("Error updating permissions for dir %s: %s", path, err)
			}
		}
		return nil
	})
}
