# ─────────────────────────────────────────────────────────────
#  Stage 1 — Build
# ─────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Cache module layer before copying source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w -X main.Version=2.4.1" \
    -o sentinel-api \
    ./cmd/main.go

# ─────────────────────────────────────────────────────────────
#  Stage 2 — Minimal runtime (~8 MB)
# ─────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/sentinel-api /sentinel-api
COPY --from=builder /build/configs/sentinel-api.yaml /etc/sentinel-api/config.yaml

VOLUME ["/reports", "/wordlists"]

ENTRYPOINT ["/sentinel-api"]
CMD ["scan", "--help"]
