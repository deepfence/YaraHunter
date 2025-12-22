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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/runner"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/deepfence/YaraHunter/pkg/threatintel"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
// var session = core.GetSession()

var (
	version         string
	sourceRuleFile  = "df-malware.json"
	malwareRuleFile = "malware.yar"
)

func main() {
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02T15:04:05Z07:00"}).
		With().Timestamp().Caller().Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts, err := config.ParseOptions()
	if err != nil {
		log.Fatal().Err(err).Msg("main: failed to parse options")
	}

	level, err := zerolog.ParseLevel(strings.ToLower(*opts.LogLevel))
	if err != nil {
		log.Warn().Str("level", *opts.LogLevel).Err(err).Msg("Invalid log level, defaulting to 'info'")
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	log.Info().Str("version", version).Msg("starting")

	extractorConfig, err := cfg.ParseConfig(*opts.ConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("main: failed to parse config")
	}

	runnerOpts := runner.RunnerOptions{
		SocketPath:           *opts.SocketPath,
		RulesPath:            *opts.RulesPath,
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

	// Download rules if updater is enabled and in CLI mode
	if *opts.SocketPath == "" && *opts.EnableUpdater {
		downloadRules(ctx, opts)
	}

	runner.StartYaraHunter(ctx, runnerOpts, extractorConfig,
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

func downloadRules(ctx context.Context, opts *config.Options) {
	log.Info().Msg("downloading malware rules")

	// Check if rules already exist
	rulesFile := filepath.Join(*opts.RulesPath, malwareRuleFile)
	if _, err := os.Stat(rulesFile); err == nil {
		log.Info().Str("file", rulesFile).Msg("rules file already exists, skipping download")
		return
	}

	// Make sure output rules directory exists
	os.MkdirAll(*opts.RulesPath, fs.ModePerm)

	// Download rules from versioned URL
	rulesURL := threatintel.RulesURL(version)
	log.Info().Str("url", rulesURL).Msg("downloading rules")

	content, err := threatintel.DownloadFile(ctx, rulesURL)
	if err != nil {
		log.Error().Err(err).Msg("failed to download rules, continuing with bundled rules if available")
		return
	}

	log.Info().Int("bytes", content.Len()).Msg("rules file size")

	// Process and write rules file
	outRuleFile := filepath.Join(*opts.RulesPath, malwareRuleFile)
	err = threatintel.ProcessTarGz(content.Bytes(), sourceRuleFile, outRuleFile, processMalwareRules)
	if err != nil {
		log.Error().Err(err).Msg("failed to process rules")
	}
}

func processMalwareRules(header *tar.Header, reader io.Reader, outPath string) error {
	var fb threatintel.FeedsBundle
	if err := json.NewDecoder(reader).Decode(&fb); err != nil {
		log.Error().Err(err).Msg("failed to decode feeds bundle")
		return err
	}

	if err := threatintel.ExportYaraRules(outPath, fb.ScannerFeeds.MalwareRules, fb.Extra); err != nil {
		log.Error().Err(err).Msg("failed to export yara rules")
		return err
	}

	return nil
}
