package scan

import (
	"context"
	"fmt"
	"sync"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/deepfence/match-scanner/pkg/extractor"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"

	genscan "github.com/deepfence/match-scanner/pkg/scanner"
)

func New(
	opts *config.Options,
	extractorConfig cfg.Config,
	yaraScannerIn *yara.Scanner,
	scanID string) *Scanner {

	obj := Scanner{
		opts,
		yaraScannerIn,
		scanID,
		cfg.Config2Filter(extractorConfig),
	}
	return &obj
}

type Scanner struct {
	*config.Options

	YaraScanner *yara.Scanner
	ScanID      string

	Filters cfg.Filters
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}

type ScanType int

const (
	DirScan ScanType = iota
	ImageScan
	ContainerScan
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DirScan:
		return "host"
	case ImageScan:
		return "image"
	case ContainerScan:
		return "container"
	}
	return ""
}

func (s *Scanner) Scan(ctx *tasks.ScanContext, stype ScanType, namespace, id string, scanID string, outputFn func(output.IOCFound, string)) error {
	var (
		extract extractor.FileExtractor
		err     error
		wg      sync.WaitGroup
	)
	switch stype {
	case DirScan:
		extract, err = extractor.NewDirectoryExtractor(s.Filters, id, true)
	case ImageScan:
		extract, err = extractor.NewImageExtractor(s.Filters, namespace, id)
	case ContainerScan:
		extract, err = extractor.NewContainerExtractor(s.Filters, namespace, id)
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	// results has to be 1 element max
	// to avoid overwriting the buffer entries
	results := make(chan []output.IOCFound)
	defer close(results)

	done := make(chan bool)
	defer close(done)

	m := [2][]output.IOCFound{}
	i := 0

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case malwares := <-results:
				for _, malware := range malwares {
					outputFn(malware, scanID)
				}
			case <-done:
				logrus.Info("scan completed")
				return
			}
		}
	}()

	genscan.ApplyScan(context.Background(), extract, func(f extractor.ExtractedFile) {
		if ctx != nil {
			err := ctx.Checkpoint("scan_phase")
			if err != nil {
				return
			}
		}

		err = ScanFile(s, f.Filename, f.Content, f.ContentSize, &m[i], "")
		if err != nil {
			logrus.Warnf("file: %v, err: %v", f.Filename, err)
		}

		results <- m[i]
		i += 1
		i %= len(m)
	})

	done <- true

	wg.Wait()
	return nil
}
