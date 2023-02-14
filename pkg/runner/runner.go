package runner

import (
	"flag"
	"sync"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/deepfence/YaraHunter/core"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/fatih/color"
)

func StartYaraHunter(newwg *sync.WaitGroup) {
	defer newwg.Done()
	flag.Parse()
	// err := runYaraUpdate()
	err := StartYaraHunterUpdater()
	if err != nil {
		core.GetSession().Log.Fatal("main: failed to serve: %v", err)
	}
	if *session.Options.SocketPath != "" {
		err := server.RunServer(*session.Options.SocketPath, PLUGIN_NAME)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve: %v", err)
		}
	} else if *session.Options.HttpPort != "" {
		core.GetSession().Log.Info("server inside port")
		err := server.RunHttpServer(*session.Options.HttpPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else if *session.Options.StandAloneHttpPort != "" {
		core.GetSession().Log.Info("server inside port")
		err := server.RunStandaloneHttpServer(*session.Options.StandAloneHttpPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else {
		runOnce()
	}

}

func runOnce() {
	var jsonOutput IOCWriter
	var err error

	// Scan container image for IOC
	if len(*session.Options.ImageName) > 0 {
		session.Log.Info("Scanning image %s for IOC...\n", *session.Options.ImageName)
		jsonOutput, err = findIOCInImage(*session.Options.ImageName)
		if err != nil {
			core.GetSession().Log.Error("error scanning the image: %s", err)
			return
		}
	}

	// Scan local directory for IOC
	if len(*session.Options.Local) > 0 {
		session.Log.Info("[*] Scanning local directory: %s\n", color.BlueString(*session.Options.Local))
		jsonOutput, err = findIOCInDir(*session.Options.Local)
		if err != nil {
			core.GetSession().Log.Error("error scanning the dir: %s", err)
			return
		}
	}

	// Scan existing container for IOC
	if len(*session.Options.ContainerId) > 0 {
		session.Log.Info("Scanning container %s for IOC...\n", *session.Options.ContainerId)
		jsonOutput, err = findIOCInContainer(*session.Options.ContainerId, *session.Options.ContainerNS)
		if err != nil {
			core.GetSession().Log.Error("error scanning the container: %s", err)
			return
		}
	}

	if jsonOutput == nil {
		core.GetSession().Log.Error("set either -local or -image-name flag")
		return
	}

	jsonFilename, err := core.GetJsonFilepath()
	if err != nil {
		core.GetSession().Log.Error("error while retrieving json output: %s", err)
		return
	}
	if jsonFilename != "" {
		err = jsonOutput.WriteIOC(jsonFilename)
		if err != nil {
			core.GetSession().Log.Error("error while writing IOC: %s", err)
			return
		}
	}
}
