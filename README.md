# Xray Exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/compassvpn/xray-exporter)][goreportcard]
[![Build Status](https://github.com/compassvpn/xray-exporter/actions/workflows/build-release-deploy.yml/badge.svg?branch=main)][build-status]

An exporter that collects Xray (and V2Ray) metrics over its [Stats API][stats-api] and exports them to Prometheus.

- [Xray Exporter](#xray-exporter)
  - [Quick Start](#quick-start)
    - [Binaries](#binaries)
    - [Docker](#docker-recommended)
  - [Tutorial](#tutorial)
  - [Grafana Dashboard](#grafana-dashboard)
  - [Digging Deeper](#digging-deeper)
  - [Special Thanks](#special-thanks)


[stats-api]: https://xtls.github.io/en/config/stats.html
[goreportcard]: https://goreportcard.com/report/github.com/compassvpn/xray-exporter
[build-status]: https://github.com/compassvpn/xray-exporter/actions/workflows/ci.yml

## Quick Start

### Binaries

The latest binaries are made available on the GitHub releases page:

### Docker

You can also find the Docker images built automatically by CI from [GitHub Container Registry](https://github.com/compassvpn/xray-exporter/pkgs/container/xray-exporter). The images are made for multi-arch. You can run it from your Raspberry Pi or any other ARM, ARM64 devices without changing the image name:

```bash
# Use a specific tag instead of the latest for production
docker run --rm -it --read-only ghcr.io/compassvpn/xray-exporter:<TAG>
```

Please note that the `latest` tag is not available. Use `main` instead if you want the latest build of the main branch.

### Grafana Dashboard

A simple Grafana dashboard is also available [here](soon). Please refer to the Grafana docs to get the steps for importing dashboards from JSON files.

## Tutorial

Before we start, let's assume you have already set up Prometheus and Grafana.

Firstly, you will need to make sure the API and statistics-related features have been enabled in your Xray _(or V2Ray)_ config file. For example:

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

As you can see, we opened two inbounds in the configuration above. The first inbound listens port 54321 on localhost and handles the API calls, which is the endpoint that the exporter scrapes. The second inbound accepts VMess connections from user `email`. If you'd like to run Xray/V2Ray and exporter on different machines, consider use `0.0.0.0` instead of `127.0.0.1` but be careful with the security risks.

Additionally, you should also enable `stats`, `api`, and `policy` settings, and setup proper routing rules in order to get traffic statistics works. For more information, please visit [xray-core API docs](https://xtls.github.io/config/api.html).

The next step is to start the exporter:

```bash
xray-exporter --xray-endpoint "127.0.0.1:54321"
## Or with Docker
docker run --rm -d --read-only ghcr.io/compassvpn/xray-exporter:main --xray-endpoint "127.0.0.1:54321"
```

The logs signifies that the exporter started to listening on the default address (`:9550`).

```plain
Xray Exporter main-a1b2c3d (built 2025-01-15T10:30:45Z)
time="2025-01-15T10:30:45Z" level=info msg="Server is ready to handle incoming scrape requests."
```

Use `--listen` option if you'd like to changing the listen address or port. You can now open `http://IP:9550` in your browser:

Click the `Scrape Xray Metrics` and the exporter will expose all metrics including Xray/V2Ray runtime and statistics data in the Prometheus metrics format, for example:

```shell
...
# HELP xray_up Indicate scrape succeeded or not
# TYPE xray_up gauge
xray_up 1
# HELP xray_uptime_seconds V2Ray uptime in seconds
# TYPE xray_uptime_seconds gauge
xray_uptime_seconds 150624
...
```

If `xray_up 1` doesn't exist in the response, that means the scrape was failed, please check out the logs (STDOUT or STDERR) of Xray Exporter for more detailed information.

We have the metrics exposed. Now let Prometheus scrapes these data points and visualize them with Grafana. Here is an example Promtheus configuration:

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

## Digging Deeper

For users who do not really care about the internal changes, but only need a mapping table, here it is:

| Runtime Metric   | Exposed Metric                     |
| :--------------- | :--------------------------------- |
| `uptime`         | `xray_uptime_seconds`             |
| `num_goroutine`  | `xray_goroutines`                 |
| `alloc`          | `xray_memstats_alloc_bytes`       |
| `total_alloc`    | `xray_memstats_alloc_bytes_total` |
| `sys`            | `xray_memstats_sys_bytes`         |
| `mallocs`        | `xray_memstats_mallocs_total`     |
| `frees`          | `xray_memstats_frees_total`       |
| `num_gc`         | `xray_memstats_num_gc`            |
| `pause_total_ns` | `xray_memstats_pause_total_ns`    |

| Statistic Metric                          | Exposed Metric                                                              |
| :---------------------------------------- | :-------------------------------------------------------------------------- |
| `inbound>>>tag-name>>>traffic>>>uplink`   | `xray_traffic_uplink_bytes_total{dimension="inbound",target="tag-name"}`   |
| `inbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="inbound",target="tag-name"}` |
| `outbound>>>tag-name>>>traffic>>>uplink`   | `xray_traffic_uplink_bytes_total{dimension="outbound",target="tag-name"}`   |
| `outbound>>>tag-name>>>traffic>>>downlink` | `xray_traffic_downlink_bytes_total{dimension="outbound",target="tag-name"}` |
| `user>>>user-email>>traffic>>>uplink`     | `xray_traffic_uplink_bytes_total{dimension="user",target="user-email"}`    |
| `user>>>user-email>>>traffic>>>downlink`  | `xray_traffic_downlink_bytes_total{dimension="user",target="user-email"}`  |
| ...                                       | ...                                                                         |


## Special Thanks

- <https://github.com/wi1dcard/v2ray-exporter>
