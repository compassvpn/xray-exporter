package geoip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	ASNUrl     = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
	CityUrl    = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
	CountryUrl = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"

	asnFile     = "GeoLite2-ASN.mmdb"
	cityFile    = "GeoLite2-City.mmdb"
	countryFile = "GeoLite2-Country.mmdb"

	// userAgent identifies this client to the upstream host.
	userAgent = "xray-exporter (+https://github.com/compassvpn/xray-exporter)"

	// dbMaxAge is how long an existing database is considered fresh enough to
	// skip re-downloading on startup.
	dbMaxAge = 7 * 24 * time.Hour

	// downloadTimeout bounds a single download attempt.
	downloadTimeout = 60 * time.Second
)

// Dir is the directory where GeoLite2 databases are stored and read from.
// Override it (e.g. from a --geoip-dir flag) before calling DownloadDB.
var Dir = "."

// ASNPath returns the path to the GeoLite2 ASN database.
func ASNPath() string { return filepath.Join(Dir, asnFile) }

// CityPath returns the path to the GeoLite2 City database.
func CityPath() string { return filepath.Join(Dir, cityFile) }

// CountryPath returns the path to the GeoLite2 Country database.
func CountryPath() string { return filepath.Join(Dir, countryFile) }

// DownloadDB downloads the latest GeoLite2 databases with retries, skipping any
// that already exist locally and are recent enough.
func DownloadDB() error {
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return fmt.Errorf("failed to create GeoIP directory %q: %w", Dir, err)
	}

	client := &http.Client{Timeout: downloadTimeout}

	dbs := []struct {
		name, url, path string
	}{
		{"ASN", ASNUrl, ASNPath()},
		{"Country", CountryUrl, CountryPath()},
		{"City", CityUrl, CityPath()},
	}

	for _, db := range dbs {
		if isFresh(db.path) {
			logrus.Infof("GeoLite2-%s database is recent, skipping download", db.name)
			continue
		}
		if err := downloadWithRetry(client, db.name, db.url, db.path); err != nil {
			return err
		}
	}
	return nil
}

// isFresh reports whether path exists, is non-empty, and was modified within dbMaxAge.
func isFresh(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() > 0 && time.Since(info.ModTime()) < dbMaxAge
}

func downloadWithRetry(client *http.Client, name, url, path string) error {
	maxRetries := 3
	var lastErr error

	for i := range maxRetries {
		logrus.Infof("Downloading GeoLite2-%s database (attempt %d/%d)...", name, i+1, maxRetries)
		err := downloadFile(client, path, url)
		if err == nil {
			logrus.Infof("GeoLite2-%s database downloaded successfully", name)
			return nil
		}
		lastErr = err
		logrus.WithError(err).Warnf("Download attempt %d for %s failed", i+1, name)
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("failed to download GeoLite2-%s database after %d attempts: %w", name, maxRetries, lastErr)
}

// downloadFile streams url to a temp file in the same directory and atomically
// renames it into place, so a failed download never corrupts an existing DB.
func downloadFile(client *http.Client, path, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}
