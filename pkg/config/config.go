package config

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

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
		data, err = ioutil.ReadFile(path.Join(configPath, "config.yaml"))
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
		data, err = ioutil.ReadFile(path.Join(dir, "config.yaml"))
		if err != nil {
			dir, _ = os.Getwd()
			data, err = ioutil.ReadFile(path.Join(dir, "config.yaml"))
			if err != nil {
				return config, err
			}
		}
	}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return config, err
	}

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
