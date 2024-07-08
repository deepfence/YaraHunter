package main

// ------------------------------------------------------------------------------
// MIT License

// Copyright (c) 2022 deepfence

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// ------------------------------------------------------------------------------

import (
	"context"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/runner"
	"github.com/deepfence/YaraHunter/pkg/server"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
// var session = core.GetSession()

func main() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", " " + path.Base(f.File) + ":" + strconv.Itoa(f.Line)
		},
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts, err := config.ParseOptions()
	if err != nil {
		log.Panicf("main: failed to parse options: %v", err)
	}
	config, err := cfg.ParseConfig(*opts.ConfigPath)
	if err != nil {
		log.Panicf("main: failed to parse options: %v", err)
	}

	runnerOpts := runner.RunnerOptions{
		SocketPath:           *opts.SocketPath,
		RulesPath:            *opts.RulesPath,
		RulesListingURL:      *opts.RulesListingURL,
		HostMountPath:        *opts.HostMountPath,
		FailOnCompileWarning: *opts.FailOnCompileWarning,
		Local:                *opts.Local,
		ImageName:            *opts.ImageName,
		ContainerID:          *opts.ContainerID,
		ConsoleURL:           *opts.ConsoleURL,
		ConsolePort:          *opts.ConsolePort,
		DeepfenceKey:         *opts.DeepfenceKey,
		OutFormat:            *opts.OutFormat,
		FailOnHighCount:      *opts.FailOnHighCount,
		FailOnMediumCount:    *opts.FailOnMediumCount,
		FailOnLowCount:       *opts.FailOnLowCount,
		FailOnCount:          *opts.FailOnCount,
		InactiveThreshold:    *opts.InactiveThreshold,
	}

	if *opts.EnableUpdater {
		go runner.ScheduleYaraHunterUpdater(ctx, runnerOpts)
	}

	runner.StartYaraHunter(ctx, runnerOpts, config,
		func(base *server.GRPCScannerServer) server.MalwareRPCServer {
			return server.MalwareRPCServer{
				GRPCScannerServer:                 base,
				UnimplementedMalwareScannerServer: pb.UnimplementedMalwareScannerServer{},
			}
		},
		func(s grpc.ServiceRegistrar, impl any) {
			pb.RegisterMalwareScannerServer(s, impl.(pb.MalwareScannerServer))
		})
}
