package scan

import (
	"os/exec"
	"strings"

	"github.com/deepfence/YaraHunter/pkg/output"
)

type ContainerExtractionResult struct {
	IOC         []output.IOCFound
	ContainerID string
}

func GetFileSystemPathsForContainer(containerID string, namespace string) ([]byte, error) {
	// fmt.Println(append([]string{"docker"},  "|", "jq" , "-r" , "'map([.Name, .GraphDriver.Data.MergedDir]) | .[] | \"\\(.[0])\\t\\(.[1])\"'"))
	return exec.Command("docker", "inspect", strings.TrimSpace(containerID)).Output()
}
