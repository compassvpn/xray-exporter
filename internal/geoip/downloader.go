package geoip

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	ASNUrl     = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
	CityUrl    = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
	CountryUrl = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"
	ASNPath    = "GeoLite2-ASN.mmdb"
	CityPath   = "GeoLite2-City.mmdb"
	CountryPath = "GeoLite2-Country.mmdb"
)

// DownloadDB downloads the latest GeoLite2 databases with retries.
func DownloadDB() error {
	if err := downloadWithRetry("ASN", ASNUrl, ASNPath); err != nil {
		return err
	}
	if err := downloadWithRetry("Country", CountryUrl, CountryPath); err != nil {
		return err
	}
	return downloadWithRetry("City", CityUrl, CityPath)
}

func downloadWithRetry(name, url, path string) error {
	maxRetries := 3
	var lastErr error

	for i := range maxRetries {
		logrus.Infof("Downloading GeoLite2-%s database (attempt %d/%d)...", name, i+1, maxRetries)
		err := downloadFile(path, url)
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

func downloadFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
