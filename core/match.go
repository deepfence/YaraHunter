package core

import (
	"github.com/deepfence/YaRadare/core/sys"
	"github.com/spf13/afero"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// IsSkippableFile Checks if the path is excluded
func IsSkippableDir(fs afero.Fs, path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range session.Config.ExcludedPaths {
		if strings.HasPrefix(path, skippablePathIndicator) || strings.HasPrefix(path, filepath.Join(baseDir, skippablePathIndicator)) {
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
