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
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/runner"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/deepfence/YaraHunter/pkg/threatintel"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
// var session = core.GetSession()

var (
	version         string
	checksumFile    = "checksum.txt"
	sourceRuleFile  = "df-malware.json"
	malwareRuleFile = "malware.yar"
)

func main() {
	log.SetOutput(os.Stderr)
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
		log.Fatalf("main: failed to parse options: %v", err)
	}

	level, err := log.ParseLevel(*opts.LogLevel)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)

	log.Infof("version: %s", version)

	config, err := cfg.ParseConfig(*opts.ConfigPath)
	if err != nil {
		log.Fatalf("main: failed to parse config: %v", err)
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

	// update rules required for cli mode
	if *opts.SocketPath == "" {
		updateRules(ctx, opts)
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

func updateRules(ctx context.Context, opts *config.Options) {
	log.Infof("check and update malware rules")

	listing, err := threatintel.FetchThreatIntelListing(ctx, version, *opts.Product, *opts.License)
	if err != nil {
		log.Fatal(err)
	}

	rulesInfo, err := listing.GetLatest(version, threatintel.MalwareDBType)
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("rulesInfo: %+v", rulesInfo)

	// make sure output rules directory exists
	os.MkdirAll(*opts.RulesPath, fs.ModePerm)

	// check if update required
	if threatintel.SkipRulesUpdate(filepath.Join(*opts.RulesPath, checksumFile), rulesInfo.Checksum) {
		log.Info("skip rules update")
		return
	}

	log.Info("download new rules")
	content, err := threatintel.DownloadFile(ctx, rulesInfo.URL)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("rules file size: %d bytes", content.Len())

	// write new checksum
	if err := os.WriteFile(
		filepath.Join(*opts.RulesPath, checksumFile), []byte(rulesInfo.Checksum), fs.ModePerm); err != nil {
		log.Fatal(err)
	}

	// write rules file
	outRuleFile := filepath.Join(*opts.RulesPath, malwareRuleFile)
	threatintel.ProcessTarGz(content.Bytes(), sourceRuleFile, outRuleFile, processMalwareRules)
}

func processMalwareRules(header *tar.Header, reader io.Reader, outPath string) error {

	var fb threatintel.FeedsBundle
	if err := json.NewDecoder(reader).Decode(&fb); err != nil {
		log.Error(err)
		return err
	}

	if err := threatintel.ExportYaraRules(outPath, fb.ScannerFeeds.MalwareRules, fb.Extra); err != nil {
		log.Error(err)
		return err
	}

	return nil
}
