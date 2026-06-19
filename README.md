# Xray Exporter

An exporter that collects Xray _(and V2Ray)_ metrics over its Stats API and exports them to Prometheus. It also provides enhanced user activity metrics by parsing access logs.

## Features

- **Runtime Metrics**: Memory usage, goroutines, uptime, GC stats
- **Traffic Statistics**: Per-user, per-inbound, per-outbound data transfer metrics  
- **User Activity Metrics**: Real-time user counts, connection patterns
- **Domain Analytics**: Most requested domains and direct IP access tracking
- **GeoIP Intelligence**: Automated Top ASNs, Countries, and Cities tracking with auto-downloading databases
- **Outbound Routing**: Traffic distribution across different outbound connections (includes blocked requests)
- **High Performance**: Optimized log parsing with circular buffers and LRU caching
- **Adaptive buffers**: Connection buffer sized by the time window and grown lazily as traffic arrives
- **Cross-platform**: Supports Linux, macOS, Windows with proper log rotation detection

## Quick Start

### Binaries

The latest binaries are made available on the [GitHub Releases Page](https://github.com/compassvpn/xray-exporter/releases/latest).

### Docker

You can also find the Docker images built automatically by CI from [GitHub Container Registry](https://github.com/compassvpn/xray-exporter/pkgs/container/xray-exporter). The images are made for multi-arch.

```bash
docker run --rm -it --read-only ghcr.io/compassvpn/xray-exporter:latest
```

Available tags:
- main _(Latest commit: may not be stable)_
- latest _(Recommended: Points to latest stable build)_
- 0.0.1 _(And any version number)_

### Grafana Dashboard

Our CompassVPN Grafana dashboard is available [here](https://grafana.com/grafana/dashboards/23181-compassvpn-dashboard/). Please refer to the Grafana docs to get the steps for importing dashboards from JSON files.

## Command Line Options

You can view all available command line options by running:

```bash
xray-exporter -h
```

Available options:

```
Usage:
  xray-exporter [OPTIONS]

Application Options:
  -l, --listen=[ADDR]:PORT         Listen address (default: :9550)
  -m, --metrics-path=PATH          Metrics path (default: /scrape)
  -e, --xray-endpoint=HOST:PORT    Xray API endpoint (default: 127.0.0.1:8080)
  -t, --scrape-timeout=N           The timeout in seconds for every individual scrape (default: 3)
  -p, --log-path=PATH              Path to Xray access log file (empty to disable user metrics) 
                                   (default: /var/log/xray/access.log)
  -w, --log-time-window=N          Time window in minutes for user metrics (default: 5)
  -g, --geoip-dir=PATH             Directory for GeoLite2 databases (default: .)
      --version                    Display the version and exit
      --log-level=LEVEL            Log level: error, warn, info, debug
                                   (env: LOG_LEVEL) (default: warn)

Help Options:
  -h, --help                       Show this help message
```

### User Activity Metrics

The exporter can parse Xray access logs to provide additional user activity insights:

- **`--log-path`**: Path to Xray access log file. Set to empty string to disable user metrics.
- **`--log-time-window`**: Time window in minutes for user activity metrics (default: 5 minutes).

These metrics help you understand user behavior, popular domains, and traffic patterns in real-time.

## Tutorial

Before we start, let's assume you have already set up Prometheus and Grafana.

First, you need to make sure the API and statistics-related features have been enabled in your Xray _(or V2Ray)_ config file. For example:

```json
{
  "routing": {
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "stats": {},
  "api": {
    "tag": "api",
    "services": [
      "StatsService"
    ]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 54321,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    },
    {
      "tag": "inbound-1",
      "port": 12345,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "email": "email",
            "id": "uuid",
            "level": 0
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
```

As you can see, we opened two inbounds in the configuration above. The first inbound listens on port 54321 on localhost and handles the API calls, which is the endpoint that the exporter scrapes. The second inbound accepts VMess connections from the user `email`. If you'd like to run Xray/V2Ray and an exporter on different machines, consider using `0.0.0.0` instead of `127.0.0.1`, but be careful with the security risks.

Additionally, you should also enable `stats`, `api`, and `policy` settings, and set up proper routing rules to get traffic statistics working. For more information, please visit [xray-core API docs](https://xtls.github.io/config/api.html) and [xray-core Stats docs](https://xtls.github.io/en/config/stats.html).

### Enable Access Log (Optional)

To get user activity metrics, enable access logging in your Xray config:

```json
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  }
}
```

The exporter will automatically parse this log file to provide additional metrics about user activity, popular domains, and traffic patterns.

### GeoIP Tracking

The exporter automatically downloads and maintains the latest GeoLite2 databases (ASN, Country, City) from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) on startup. No manual setup is required.

These databases enable high-precision tracking of:
- **Top ASNs**: Identify which networks your users are coming from.
- **Top Countries**: See geographic distribution by country.
- **Top Cities**: Granular city-level connection statistics.

### Start the Exporter

```bash
# Basic usage (gRPC metrics only)
xray-exporter --xray-endpoint "127.0.0.1:54321"

# With user activity metrics from logs
xray-exporter --xray-endpoint "127.0.0.1:54321" --log-path "/var/log/xray/access.log"

# With custom time window for user metrics
xray-exporter --xray-endpoint "127.0.0.1:54321" --log-time-window 10

# Or with Docker
docker run --rm -d --read-only \
  -v /var/log/xray:/var/log/xray:ro \
  ghcr.io/compassvpn/xray-exporter:latest \
  --xray-endpoint "xray:54321" \
  --log-path "/var/log/xray/access.log"
```

The logs signify that the exporter started to listen on the default address (`:9550`).

```plain
Xray Exporter XXX-a1b2c3d (built 2025-01-01T21:00:00Z)
time="2025-01-15T10:30:45Z" level=info msg="Log parser started successfully"
time="2025-01-15T10:30:45Z" level=info msg="Server starting on :9550"
```

Use `--listen` option if you'd like to change the listen address or port. You can open `http://ip:9550` in your browser:

Click the `Scrape Xray Metrics` and the exporter will expose all metrics, including Xray/V2Ray runtime and statistics data in the Prometheus metrics format, for example:

```shell
...
# HELP xray_up Indicate scrape succeeded or not
# TYPE xray_up gauge
xray_up 1
# HELP xray_uptime_seconds Xray uptime in seconds
# TYPE xray_uptime_seconds gauge
xray_uptime_seconds 150624

# User activity metrics (if log parsing enabled)
# HELP xray_unique_users Number of unique users in time window
# TYPE xray_unique_users gauge
xray_unique_users 42
# HELP xray_total_connections Total number of connections in time window
# TYPE xray_total_connections gauge  
xray_total_connections 1337
...
```

If `xray_up 1` doesn't exist in the response, that means the scrape failed. Please check out the logs (STDOUT or STDERR) of Xray Exporter for more detailed information.

We have the metrics exposed. Now let Prometheus scrape these data points and visualize them with Grafana. Here is an example Prometheus configuration:

```yaml
global:
  scrape_interval: 15s
  scrape_timeout: 5s

scrape_configs:
  - job_name: xray
    metrics_path: /scrape
    static_configs:
      - targets: [IP:9550]
```

To learn more about Prometheus, please visit the [official docs](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).

## Available Metrics

### Runtime Metrics

| Runtime Metric   | Exposed Metric                     | Description |
| :--------------- | :--------------------------------- | :---------- |
| `uptime`         | `xray_uptime_seconds`             | Xray uptime in seconds |
| `num_goroutine`  | `xray_goroutines`                 | Number of goroutines |
| `alloc`          | `xray_memstats_alloc_bytes`       | Bytes allocated and in use |
| `total_alloc`    | `xray_memstats_alloc_bytes_total` | Total bytes allocated |
| `sys`            | `xray_memstats_sys_bytes`         | Bytes obtained from system |
| `mallocs`        | `xray_memstats_mallocs_total`     | Total number of mallocs |
| `frees`          | `xray_memstats_frees_total`       | Total number of frees |
| `num_gc`         | `xray_memstats_num_gc`            | Number of GC cycles |
| `pause_total_ns` | `xray_memstats_pause_total_ns`    | Total GC pause time |

### Traffic Statistics

| Statistic Metric                          | Exposed Metric                                                              |
| :---------------------------------------- | :-------------------------------------------------------------------------- |
| `inbound>>>tag-name>>>traffic>>>uplink`   | `xray_traffic_uplink_bytes_total{dimension="inbound",target="tag-name"}`   |
| `inbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="inbound",target="tag-name"}` |
| `outbound>>>tag-name>>>traffic>>>uplink`   | `xray_traffic_uplink_bytes_total{dimension="outbound",target="tag-name"}`   |
| `outbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="outbound",target="tag-name"}` |
| `user>>>user-email>>>traffic>>>uplink`     | `xray_traffic_uplink_bytes_total{dimension="user",target="user-email"}`    |
| `user>>>user-email>>>traffic>>>downlink`  | `xray_traffic_downlink_bytes_total{dimension="user",target="user-email"}`  |

### User Activity Metrics (Log Parsing)

| Metric | Description | Labels |
| :----- | :---------- | :----- |
| `xray_unique_users` | Number of unique users active in the time window | - |
| `xray_total_connections` | Total number of connections in the time window | - |
| `xray_requested_domain_ip_total` | Total requests per domain or IP address | `target` |
| `xray_outbound_requests_total` | Total requests per outbound connection | `outbound` |
| `xray_asns_total` | Total requests per ASN | `asn`, `org` |
| `xray_countries_total` | Total requests per country | `country` |
| `xray_cities_total` | Total requests per city | `city`, `country` |

### Core Metrics

| Metric | Description |
| :----- | :---------- |
| `xray_up` | Whether the last scrape was successful (1 = success, 0 = failure) |
| `xray_scrape_duration_seconds` | Time spent scraping metrics from Xray |
| `xray_scrapes_total` | Total number of scrapes performed |

### Recommended Grafana Queries

Use these queries to visualize the new GeoIP metrics:

These series are gauges (top-N request counts since the parser started, periodically trimmed), so query the value directly rather than with `rate()`/`increase()`:

- **Top 10 ASNs**: `topk(10, sum by (asn, org) (xray_asns_total))`
- **Top 10 Countries**: `topk(10, sum by (country) (xray_countries_total))`
- **Top 10 Cities**: `topk(10, sum by (city, country) (xray_cities_total))`

## Performance & Scalability

This exporter is optimized for high-traffic proxy services:

- **Memory Efficient**: Circular buffers prevent memory leaks from connection tracking
- **High Performance**: Optimized log parsing with smart caching and buffering
- **Auto-scaling**: Buffer sizes automatically adapt to time window settings
- **Concurrent Safe**: Lock-free operations where possible, minimal lock contention
- **Production Ready**: Handles log rotation, file truncation, and network failures gracefully

## Development

Before committing, run this single command to format, vet, and build the
project. It mirrors the checks CI runs, so if it passes locally the lint gate
will pass too:

```bash
gofmt -w . && go vet ./... && go build ./...
```

- `gofmt -w .` rewrites any mis-formatted files in place
- `go vet ./...` catches common mistakes
- `go build ./...` confirms everything compiles

## Special Thanks

- <https://github.com/wi1dcard/v2ray-exporter>
