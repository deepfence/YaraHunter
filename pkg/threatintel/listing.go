package threatintel

import (
	"sort"
	"time"
)

const (
	MalwareDBType = "malware"
	SecretDBType  = "secret"
)

type Listing struct {
	Available map[string][]Entry `json:"available"`
}

type Entry struct {
	Built    time.Time `json:"built"`
	Version  string    `json:"version"`
	Type     string    `json:"type"`
	URL      string    `json:"url"`
	Checksum string    `json:"checksum"`
}

func (l *Listing) GetLatest(version, dbType string) (Entry, error) {

	entries := []Entry{}

	for _, e := range l.Available[version] {
		if e.Type == dbType {
			entries = append(entries, e)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Built.Before(entries[j].Built)
	})

	if len(entries) >= 1 {
		return entries[len(entries)-1], nil
	}

	return Entry{}, ErrDatabaseNotFound

}

func (l *Listing) GetLatestN(version string, dbType ...string) ([]Entry, error) {

	entries := []Entry{}

	for _, e := range dbType {
		dbinfo, err := l.GetLatest(version, e)
		if err != nil && err != ErrDatabaseNotFound {
			return entries, err
		}
		entries = append(entries, dbinfo)
	}

	return entries, nil

}
