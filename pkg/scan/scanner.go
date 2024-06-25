package scan

import (
	"context"
	"fmt"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/deepfence/match-scanner/pkg/extractor"
	"github.com/hillu/go-yara/v4"

	genscan "github.com/deepfence/match-scanner/pkg/scanner"
)

func New(
	opts *config.Options,
	yaraconfig *config.Config,
	extractorConfig cfg.Config,
	yaraScannerIn *yara.Scanner,
	scanID string) *Scanner {

	obj := Scanner{
		opts,
		yaraconfig,
		yaraScannerIn,
		scanID,
		cfg.Config2Filter(extractorConfig),
	}
	return &obj
}

type Scanner struct {
	*config.Options
	*config.Config

	YaraScanner *yara.Scanner
	ScanID      string

	Filters cfg.Filters
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}

type ScanType int

const (
	DIR_SCAN ScanType = iota
	IMAGE_SCAN
	CONTAINER_SCAN
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DIR_SCAN:
		return "host"
	case IMAGE_SCAN:
		return "image"
	case CONTAINER_SCAN:
		return "container"
	}
	return ""
}

func (s *Scanner) Scan(stype ScanType, namespace, id string, scanID string, outputFn func(output.IOCFound, string)) error {
	var (
		extract extractor.FileExtractor
		//isContainer bool
		//trim        bool
		err error
	)
	switch stype {
	case DIR_SCAN:
		extract, err = extractor.NewDirectoryExtractor(s.Filters, id)
		//trim = true
	case IMAGE_SCAN:
		extract, err = extractor.NewImageExtractor(s.Filters, namespace, id)
	case CONTAINER_SCAN:
		extract, err = extractor.NewContainerExtractor(s.Filters, namespace, id)
		//isContainer = true
		//trim = true
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	results := make(chan []output.IOCFound)
	defer close(results)

	go func() {
		for malwares := range results {
			for _, malware := range malwares {
				outputFn(malware, scanID)
			}
		}
	}()

	m := []output.IOCFound{}
	genscan.ApplyScan(context.Background(), extract, func(f extractor.ExtractedFile) {
		m = m[:0]
		ScanFile(s, f.Filename, f.Content, &m, "")
		results <- m
	})
	return nil
}
