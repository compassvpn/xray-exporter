package geoip

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// Keeps db on the newest release of a db-ip subscription. It opens the file
// already on disk before returning, so the log parser never starts without it,
// then checks db-ip in the background now and once a day after that.
func WatchDBIP(db *DB, key, product string) {
	var current string
	if found, _ := filepath.Glob(filepath.Join(Dir, "dbip-*.mmdb")); len(found) > 0 && db.Open(found[0]) {
		current = found[0]
	}
	go watchDBIP(db, key, product, current)
}

func watchDBIP(db *DB, key, product, current string) {
	retry := 3 * time.Hour
	for {
		wait := 24 * time.Hour
		path, err := fetchDBIP(key, product)
		switch {
		case err != nil:
			// A failed download can be over a gigabyte, so back off: 3, 6, 12, then 24 hours.
			wait, retry = retry, min(2*retry, wait)
			logrus.WithError(err).Warnf("Failed to update the db-ip database, retrying in %s", wait)
		case path != current && db.Open(path):
			current = path
			old, _ := filepath.Glob(filepath.Join(Dir, "dbip-*.mmdb"))
			for _, f := range old {
				if f != path {
					_ = os.Remove(f)
				}
			}
		}
		if err == nil {
			retry = 3 * time.Hour
		}
		time.Sleep(wait)
	}
}

// Asks db-ip for its latest release and downloads it unless it's already on
// disk. Returns the path of the unpacked file.
func fetchDBIP(key, product string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	var release struct {
		MMDB struct {
			URL     string `json:"url"`
			SHA1Sum string `json:"sha1sum"`
		} `json:"mmdb"`
	}
	resp, err := get(ctx, fmt.Sprintf("https://db-ip.com/account/%s/db/%s/", key, product))
	if err != nil {
		return "", err
	}
	err = json.NewDecoder(resp.Body).Decode(&release)
	_ = resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("failed to read the db-ip release info: %w", err)
	}
	if release.MMDB.URL == "" || release.MMDB.SHA1Sum == "" {
		return "", fmt.Errorf("db-ip has no mmdb release of %s for this key", product)
	}

	path := filepath.Join(Dir, "dbip-"+release.MMDB.SHA1Sum+".mmdb")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return "", err
	}
	// A killed download leaves its temp file behind, and these run over a gigabyte.
	leftovers, _ := filepath.Glob(filepath.Join(Dir, "dbip.tmp-*"))
	for _, f := range leftovers {
		_ = os.Remove(f)
	}

	logrus.Info("Downloading the db-ip database...")
	resp, err = get(ctx, release.MMDB.URL)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	tmp, err := os.CreateTemp(Dir, "dbip.tmp-*")
	if err != nil {
		return "", err
	}
	// Both are no-ops once the file is closed and renamed below.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, gz); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	logrus.Info("db-ip database downloaded successfully")
	return path, nil
}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	// Setting this ourselves stops Go from gunzipping the body behind our back,
	// which would break the gunzip.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("bad status from %s: %s", req.URL.Host, resp.Status)
	}
	return resp, nil
}
