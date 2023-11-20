package utils

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

// create file create a file if it does not exist
func CreateFile(dest string, filename string) (*os.File, error) {
	if !PathExists(dest) {
		err := os.MkdirAll(dest, 0755)
		if err != nil {
			return nil, err
		}
	}
	file, err := os.Create(filepath.Join(dest, filename))
	if err != nil {
		return nil, err
	}
	return file, nil
}

// check if file exists
func PathExists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		// Schrodinger: file may or may not exist. See err for details.
		logrus.Error(err)
		return false
	}
}

func DownloadFile(dURL string, dest string) (string, error) {
	// fmt.Println("the dynamic url is",dUrl)
	fullURLFile := dURL

	// Build fileName from fullPath
	fileURL, err := url.Parse(fullURLFile)
	if err != nil {
		return "", err
	}
	// fmt.Println("the dynamic url is",fileURL)
	path := fileURL.Path
	segments := strings.Split(path, "/")
	fileName := segments[len(segments)-1]

	// Create blank file
	file, err := os.Create(filepath.Join(dest, fileName))
	if err != nil {
		return "", err
	}
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	// Put content on file
	resp, err := client.Get(fullURLFile)
	// fmt.Println(" The dynamic url is ",fileName)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return fileName, nil

}

func Untar(d *os.File, r io.Reader) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}
		// check the file type
		if header.Typeflag == tar.TypeReg && strings.Contains(header.Name, ".yar") {
			if _, err := io.Copy(d, tr); err != nil {
				return err
			}
			d.Close()
		}
	}
}

func GetDfInstallDir() string {
	installDir, exists := os.LookupEnv("DF_INSTALL_DIR")
	if exists {
		return installDir
	} else {
		return ""
	}
}
