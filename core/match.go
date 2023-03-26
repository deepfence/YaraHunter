package core

import (
	"os"
	"path/filepath"
	"strings"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// IsSkippableFile Checks if the path is excluded
func IsSkippableContainerRuntimeDir(path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range session.Config.ExcludedContainerPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
		if strings.Contains(path, skippablePathIndicator) || strings.Contains(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
	}

	return false
}

// IsSkippableFile Checks if the path is excluded
func IsSkippableDir(path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range session.Config.ExcludedPaths {
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
func IsSkippableFileExtension(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, skippableExt := range session.Config.ExcludedExtensions {
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
				GetSession().Log.Error("Failed to change dir %s permission: %s", path, err)
			}
		}
		return nil
	})
}
