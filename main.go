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
	"sync"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/runner"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	log "github.com/sirupsen/logrus"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
// var session = core.GetSession()

var wg sync.WaitGroup

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
	config, err := config.ParseConfig(*opts.ConfigPath)
	if err != nil {
		log.Panicf("main: failed to parse options: %v", err)
	}
	executorConfig, err := cfg.ParseConfig(*opts.ExecutorConfigPath)
	if err != nil {
		log.Panicf("main: failed to parse options: %v", err)
	}

	if *opts.EnableUpdater {
		wg.Add(1)
		err := runner.StartYaraHunterUpdater(*opts.ConfigPath, *opts.RulesPath, *opts.RulesListingURL)
		if err != nil {
			log.Panicf("main: failed to start updater: %v", err)
		}
		go runner.ScheduleYaraHunterUpdater(ctx, opts)
	}

	go runner.StartYaraHunter(ctx, opts, config, executorConfig)
	<-ctx.Done()
}
