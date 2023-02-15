package core

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deepfence/YaRadare/core/sys"
	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// IsSkippableFile Checks if the path is excluded
func IsSkippableContainerRuntimeDir(fs afero.Fs, excludedContainerPaths []string, path string, baseDir, hostMountPath string) bool {
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range excludedContainerPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
		if strings.Contains(path, skippablePathIndicator) || strings.Contains(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
	}

	file, err := fs.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	f, ok := file.(*os.File)
	if !ok {
		return false
	}
	var buf syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &buf); err != nil {
		return false
	}
	switch uint32(buf.Type) {
	case
		// pseudo filesystems
		constants.BDEVFS_MAGIC,
		constants.BINFMTFS_MAGIC,
		constants.CGROUP_SUPER_MAGIC,
		constants.DEBUGFS_MAGIC,
		constants.EFIVARFS_MAGIC,
		constants.FUTEXFS_SUPER_MAGIC,
		constants.HUGETLBFS_MAGIC,
		constants.PIPEFS_MAGIC,
		constants.PROC_SUPER_MAGIC,
		constants.SELINUX_MAGIC,
		constants.SMACK_MAGIC,
		constants.SYSFS_MAGIC,
		// network filesystems
		constants.AFS_FS_MAGIC,
		constants.OPENAFS_FS_MAGIC,
		constants.CEPH_SUPER_MAGIC,
		constants.CIFS_MAGIC_NUMBER,
		constants.CODA_SUPER_MAGIC,
		constants.NCP_SUPER_MAGIC,
		constants.NFS_SUPER_MAGIC,
		constants.OCFS2_SUPER_MAGIC,
		constants.SMB_SUPER_MAGIC,
		constants.V9FS_MAGIC,
		constants.VMBLOCK_SUPER_MAGIC,
		constants.XENFS_SUPER_MAGIC:
		return true
	}
	return false
}

// IsSkippableFile Checks if the path is excluded
func IsSkippableDir(fs afero.Fs, config config.Config, path, baseDir, hostMountPath string) bool {
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range config.ExcludedPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
		if strings.Contains(path, skippablePathIndicator) || strings.Contains(path, filepath.Join(baseDir, skippablePathIndicator)) {
			return true
		}
	}

	file, err := fs.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	f, ok := file.(*os.File)
	if !ok {
		return false
	}
	var buf syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &buf); err != nil {
		return false
	}
	switch uint32(buf.Type) {
	case
		// pseudo filesystems
		sys.BDEVFS_MAGIC,
		sys.BINFMTFS_MAGIC,
		sys.CGROUP_SUPER_MAGIC,
		sys.DEBUGFS_MAGIC,
		sys.EFIVARFS_MAGIC,
		sys.FUTEXFS_SUPER_MAGIC,
		sys.HUGETLBFS_MAGIC,
		sys.PIPEFS_MAGIC,
		sys.PROC_SUPER_MAGIC,
		sys.SELINUX_MAGIC,
		sys.SMACK_MAGIC,
		sys.SYSFS_MAGIC,
		// network filesystems
		sys.AFS_FS_MAGIC,
		sys.OPENAFS_FS_MAGIC,
		sys.CEPH_SUPER_MAGIC,
		sys.CIFS_MAGIC_NUMBER,
		sys.CODA_SUPER_MAGIC,
		sys.NCP_SUPER_MAGIC,
		sys.NFS_SUPER_MAGIC,
		sys.OCFS2_SUPER_MAGIC,
		sys.SMB_SUPER_MAGIC,
		sys.V9FS_MAGIC,
		sys.VMBLOCK_SUPER_MAGIC,
		sys.XENFS_SUPER_MAGIC:
		return true
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
	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				log.Errorf("Error updating permissions for dir %s: %s", path, err)
			}
		}
		return nil
	})
}
