package config

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ExcludedExtensions     []string `yaml:"exclude_extensions"`
	ExcludedPaths          []string `yaml:"exclude_paths"`
	ExcludedContainerPaths []string `yaml:"exclude_container_paths"`
}

func ParseConfig(configPath string) (*Config, error) {
	config := &Config{}
	var (
		data []byte
		err  error
	)

	if len(configPath) > 0 {
		data, err = os.ReadFile(path.Join(configPath, "config.yaml"))
		if err != nil {
			return config, err
		}
	} else {
		// Trying to first find the configuration next to executable
		// Helps e.g. with Drone where workdir is different than shhgit dir
		ex, err := os.Executable()
		if err != nil {
			return config, err
		}
		dir := filepath.Dir(ex)
		data, err = os.ReadFile(path.Join(dir, "config.yaml"))
		if err != nil {
			dir, _ = os.Getwd()
			data, err = os.ReadFile(path.Join(dir, "config.yaml"))
			if err != nil {
				return config, err
			}
		}
	}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return config, err
	}

	pathSeparator := string(os.PathSeparator)
	var excludedPaths []string
	for _, path := range config.ExcludedPaths {
		excludedPaths = append(excludedPaths, strings.Replace(path, "{sep}", pathSeparator, -1))
	}
	config.ExcludedPaths = excludedPaths

	var excludedContainerPaths []string
	for _, path := range config.ExcludedContainerPaths {
		excludedContainerPaths = append(excludedContainerPaths, strings.Replace(path, "{sep}", pathSeparator, -1))
	}
	config.ExcludedContainerPaths = excludedContainerPaths

	return config, nil
}

// todo: check if this is needed
// func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	*c = Config{}
// 	type plain Config

// 	err := unmarshal((*plain)(c))

// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }
