# Xray Exporter

A Prometheus exporter for Xray and V2Ray. It reads runtime and traffic statistics from Xray's gRPC Stats API, and optionally parses the access log to report who is connecting, from where, and to which destinations.

Rotation is detected by inode, so log parsing is unix only. Linux and macOS builds are published.

## What you can put on a dashboard

From the access log:

- Unique users and open connections over a rolling window
- Top requested domains, with subdomains folded into their registrable domain
- Top direct IP destinations, with localhost, private ranges, and the usual public DNS resolvers filtered out
- Top ASNs with their network name, top countries, and top cities, resolved from GeoLite2 databases the exporter downloads and refreshes on its own
- A world map of connections by country or city
- How traffic splits across your outbounds, including whichever tag your config uses for blocked traffic

From the Stats API:

- Bytes up and down per inbound and per outbound
- Bytes up and down per user, off by default because it is one series per user
- Xray process health: uptime, goroutine count, heap usage, and GC pauses
- Whether the last scrape worked and how long it took

Our CompassVPN dashboard is published on [grafana.com](https://grafana.com/grafana/dashboards/23181-compassvpn-dashboard/) if you want a starting point. The [metrics reference](#metrics-reference) below has the queries if you would rather build your own.

## Install

### Binaries

Linux (amd64, arm64, arm) and macOS (amd64, arm64) builds are on the [releases page](https://github.com/compassvpn/xray-exporter/releases/latest).

### Docker

Multi-arch images (amd64, arm64, arm/v7) are published to the [GitHub Container Registry](https://github.com/compassvpn/xray-exporter/pkgs/container/xray-exporter):

```bash
docker run --rm -it ghcr.io/compassvpn/xray-exporter:latest
```

Three kinds of tag are available: `latest` follows the newest release, a version tag like `v0.6.6` pins to one release, and `main` is built from the tip of the main branch and may not be stable.

## Setup

### Xray config

The exporter talks to Xray's Stats API, so the `api`, `stats`, and `policy` blocks all need to be present, along with a routing rule that sends the API inbound to the API outbound:

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

There are two inbounds here. The first listens on port 54321 on localhost and answers the API calls the exporter makes. The second is an ordinary VMess inbound for the user `email`. If the exporter runs on a different machine than Xray, listen on `0.0.0.0` instead of `127.0.0.1` and firewall the port, since anyone who can reach it can read your stats.

See the [xray-core API docs](https://xtls.github.io/config/api.html) and [stats docs](https://xtls.github.io/en/config/stats.html) for the details.

### Access log

Everything under [user activity](#user-activity) below comes from the access log, which is off unless you turn it on:

```json
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  }
}
```

## Running it

### Starting the exporter

```bash
# gRPC metrics only
xray-exporter --xray-endpoint "127.0.0.1:54321"

# plus user activity from the access log
xray-exporter --xray-endpoint "127.0.0.1:54321" --log-path "/var/log/xray/access.log"

# with a 10 minute window instead of the default 5
xray-exporter --xray-endpoint "127.0.0.1:54321" --log-time-window 10
```

Or in Docker, with the log mounted read-only and a writable directory for the GeoIP databases:

```bash
docker run --rm -d \
  -v /var/log/xray:/var/log/xray:ro \
  -v xray-exporter-geoip:/geoip \
  ghcr.io/compassvpn/xray-exporter:latest \
  --xray-endpoint "xray:54321" \
  --log-path "/var/log/xray/access.log" \
  --geoip-dir /geoip
```

The GeoLite2 databases are written to `--geoip-dir`, which defaults to the working directory. Inside the container that is `/`, so a container started with `--read-only` and no writable volume cannot download them. That is not fatal, but the ASN, country, and city metrics stay empty.

On startup you should see:

```plain
Xray Exporter XXX-a1b2c3d (built 2025-01-01T21:00:00Z)
time="2025-01-15T10:30:45Z" level=info msg="Log parser started successfully"
time="2025-01-15T10:30:45Z" level=info msg="Server starting on :9550"
```

Open `http://ip:9550` and follow the `Scrape Xray Metrics` link to see the output. If `xray_up 1` is missing from the response, the scrape failed and the exporter logs will say why.

### Prometheus

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

### Grafana

Import [dashboard 23181](https://grafana.com/grafana/dashboards/23181-compassvpn-dashboard/) from grafana.com, or build your own from the [metrics reference](#metrics-reference).

## Flags

| Flag | Default | Description |
| :--- | :------ | :---------- |
| `-l, --listen [ADDR]:PORT` | `:9550` | Address to listen on |
| `-m, --metrics-path PATH` | `/scrape` | Path that serves the Xray metrics |
| `-e, --xray-endpoint HOST:PORT` | `127.0.0.1:8080` | Xray API endpoint |
| `-t, --scrape-timeout N` | `5` | Timeout in seconds for each individual scrape |
| `-u, --user-traffic-metrics` | off | Export per-user traffic byte counters |
| `-p, --log-path PATH` | `/var/log/xray/access.log` | Access log to parse. Empty disables the log metrics |
| `-w, --log-time-window N` | `5` | Window in minutes for the log metrics |
| `-g, --geoip-dir PATH` | `.` | Directory for the GeoLite2 databases |
| `--log-level LEVEL` | `info` | `error`, `warn`, `info`, or `debug`. Also read from `LOG_LEVEL` |
| `--log-format FORMAT` | `text` | `text` or `json`. Also read from `LOG_FORMAT` |
| `--version` | | Print the version and exit |

`xray-exporter -h` prints the same list.

## Metrics reference

### Xray runtime

| Xray stat | Exported metric | Description |
| :-------- | :-------------- | :---------- |
| `uptime` | `xray_uptime_seconds` | Xray uptime in seconds |
| `num_goroutine` | `xray_goroutines` | Number of goroutines |
| `alloc` | `xray_memstats_alloc_bytes` | Bytes allocated and in use |
| `total_alloc` | `xray_memstats_alloc_bytes_total` | Total bytes allocated |
| `sys` | `xray_memstats_sys_bytes` | Bytes obtained from the OS |
| `mallocs` | `xray_memstats_mallocs_total` | Total number of mallocs |
| `frees` | `xray_memstats_frees_total` | Total number of frees |
| `num_gc` | `xray_memstats_num_gc` | Number of GC cycles |
| `pause_total_ns` | `xray_memstats_pause_total_ns` | Total GC pause time |

### Traffic

| Xray stat | Exported metric |
| :-------- | :-------------- |
| `inbound>>>tag-name>>>traffic>>>uplink` | `xray_traffic_uplink_bytes_total{dimension="inbound",target="tag-name"}` |
| `inbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="inbound",target="tag-name"}` |
| `outbound>>>tag-name>>>traffic>>>uplink` | `xray_traffic_uplink_bytes_total{dimension="outbound",target="tag-name"}` |
| `outbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="outbound",target="tag-name"}` |
| `user>>>user-email>>>traffic>>>uplink` | `xray_traffic_uplink_bytes_total{dimension="user",target="user-email"}` |
| `user>>>user-email>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="user",target="user-email"}` |

The `dimension="user"` rows are opt-in. Pass `--user-traffic-metrics` to turn them on. Every user becomes its own series with no top-N cap, so only do this where the set of users is small and known.

### User activity

Only exported when `--log-path` points at a readable access log.

| Metric | Type | Description | Labels |
| :----- | :--- | :---------- | :----- |
| `xray_requested_domain_ip_total` | counter | Requests per domain or IP since startup | `target` |
| `xray_asns_total` | counter | Requests per ASN since startup | `asn`, `org` |
| `xray_countries_total` | counter | Requests per country since startup | `country` |
| `xray_cities_total` | counter | Requests per city since startup | `city`, `country` |
| `xray_unique_users` | gauge | Unique users active in the time window | |
| `xray_total_connections` | gauge | Connections in the time window | |
| `xray_outbound_requests` | gauge | Requests per outbound in the time window | `outbound` |

#### Querying them

The counters only go up. Rotating the log, truncating it, or a quiet spell long enough for the window to age every key out all leave them alone. Only restarting the exporter puts them back to zero, which Prometheus reads as an ordinary counter reset.

Which keys get exported is a separate question from their value, and it depends on how busy each key is in the current window. A target that goes quiet falls out of the top-N and its series ends there. When traffic comes back the series comes back at a higher value, never a lower one. The limits are 50 domains, 50 direct IPs, 50 outbounds, and 20 each for ASNs, countries, and cities.

The three gauges describe the window as it is right now, so `rate()` and `increase()` do not mean anything on them.

Since the rest are counters, wrap them in `increase()` over the panel range:

```promql
topk(10, sum by (asn, org) (increase(xray_asns_total[$__range])))
topk(10, sum by (country) (increase(xray_countries_total[$__range])))
topk(10, sum by (city, country) (increase(xray_cities_total[$__range])))
topk(10, sum by (target) (increase(xray_requested_domain_ip_total[$__range])))
```

### Exporter health

| Metric | Description |
| :----- | :---------- |
| `xray_up` | Whether the last scrape succeeded (1 or 0) |
| `xray_scrape_duration_seconds` | Time spent scraping Xray |
| `xray_scrapes_total` | Number of scrapes performed |

## Memory

Connection timestamps go into a circular buffer sized from the time window: 500k entries for windows of 5 minutes or less, up to 5M above 30 minutes. It grows with traffic instead of being allocated upfront, so a quiet server never pays for the full buffer. Per-key maps are capped at 10,000 keys as a backstop against random-subdomain floods, which sits far above any top-N that actually gets exported. IP filter lookups are cached in an LRU so repeated addresses skip the network range checks.

## Development

Before committing, run the checks CI runs:

```bash
gofmt -w . && go vet ./... && go build ./...
```

If that passes locally, the lint gate will pass too.

## Special thanks

- <https://github.com/wi1dcard/v2ray-exporter>
