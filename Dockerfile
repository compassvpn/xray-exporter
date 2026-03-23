FROM alpine:3.24
RUN apk --no-cache add ca-certificates
ARG TARGETARCH
EXPOSE 9550
COPY --chmod=0755 dist/xray-exporter-linux-${TARGETARCH} /usr/bin/xray-exporter
ENTRYPOINT [ "/usr/bin/xray-exporter" ]
