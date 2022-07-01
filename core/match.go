package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// IsSkippableFile Checks if the path is blacklisted
func IsSkippableDir(path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range session.Config.BlacklistedPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
	}

	return false
}

// IsSkippableFileExtension Checks if the file extension is blacklisted
func IsSkippableFileExtension(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, skippableExt := range session.Config.BlacklistedExtensions {
		if extension == skippableExt {
			return true
		}
	}
	return false
}

// ContainsBlacklistedString Checks if the input contains a blacklisted string
func ContainsBlacklistedString(input []byte) bool {
	for _, blacklistedString := range session.Config.BlacklistedStrings {
		blacklistedByteStr := []byte(blacklistedString)
		if bytes.Contains(input, blacklistedByteStr) {
			GetSession().Log.Debug("Blacklisted string %s matched", blacklistedString)
			return true
		}
	}

	return false
}

// UpdateDirsPermissionsRW Update permissions for dirs in container images, so that they can be properly deleted
func UpdateDirsPermissionsRW(dir string) {
	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				GetSession().Log.Error("Failed to change dir %s permission: %s", path, err)
			}
		}
		return nil
	})
}
