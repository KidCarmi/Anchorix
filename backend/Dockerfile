# --- Build stage ---
# Floating major-version pin: tracks the latest patched 1.x release.
# This matches the "stable" pin in our CI workflows so the binary we
# ship is built against the same stdlib govulncheck blesses.
FROM golang:1-alpine AS build
WORKDIR /src

# Cache deps first.
COPY go.mod go.sum* ./
RUN go mod download

# Copy source.
COPY . .

# Build a static binary.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/anchorix ./cmd/anchorix

# --- Runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/anchorix /anchorix
COPY --from=build /src/migrations /migrations
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/anchorix"]
CMD ["serve"]
