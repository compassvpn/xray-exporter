package geoip

import (
	"cmp"
	"net"
	"strconv"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sirupsen/logrus"
)

// What one IP resolves to. Empty fields mean no database had it.
type Info struct {
	Country, City, ASN, Org string
}

// The fields we read from an MMDB record. GeoLite2 keeps the ASN and org at the
// top level, while db-ip and other Enterprise-style files keep them under traits.
type record struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	ASN    uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
	Traits struct {
		ASN uint32 `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
		ISP string `maxminddb:"isp"`
	} `maxminddb:"traits"`
}

// Holds the open MMDB files. A lookup checks them in order and the first file
// with a value wins. Open can swap the files while lookups are running.
type DB struct {
	mu      sync.RWMutex
	readers []*maxminddb.Reader
}

// Replaces the open files with the ones at paths, skipping any that fail to
// open. If none of them open, the current files stay and it returns false.
func (db *DB) Open(paths ...string) bool {
	var readers []*maxminddb.Reader
	for _, path := range paths {
		r, err := maxminddb.Open(path)
		if err != nil {
			logrus.WithError(err).Warnf("Failed to open GeoIP database %s", path)
			continue
		}
		readers = append(readers, r)
	}
	if len(readers) == 0 {
		return false
	}
	db.swap(readers)
	return true
}

func (db *DB) Close() { db.swap(nil) }

// The files are mmapped, so the old ones are closed only after the write lock
// guarantees no lookup is still reading them.
func (db *DB) swap(readers []*maxminddb.Reader) {
	db.mu.Lock()
	old := db.readers
	db.readers = readers
	db.mu.Unlock()
	for _, r := range old {
		_ = r.Close()
	}
}

func (db *DB) Lookup(ip net.IP) Info {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var info Info
	for _, r := range db.readers {
		var rec record
		if err := r.Lookup(ip, &rec); err != nil {
			continue
		}
		info.Country = cmp.Or(info.Country, rec.Country.IsoCode)
		info.City = cmp.Or(info.City, rec.City.Names.En)
		if asn := cmp.Or(rec.ASN, rec.Traits.ASN); info.ASN == "" && asn != 0 {
			info.ASN = strconv.FormatUint(uint64(asn), 10)
			info.Org = cmp.Or(rec.Org, rec.Traits.Org, rec.Traits.ISP)
		}
	}
	return info
}
