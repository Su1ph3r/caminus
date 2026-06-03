# Caminus container image. Doubles as the GitHub Action image (action.yml
# overrides the entrypoint to /entrypoint.sh, which maps Action inputs to flags).
#
#   docker build -t caminus .
#   docker run --rm -v "$PWD:/repo" -w /repo caminus scan .
#
# This is the dependency-free core build (no -tags cloud|yaml). Cloud
# enumeration and the structural-YAML engine are opt-in source builds.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /usr/local/bin/caminus ./cmd/caminus

FROM alpine:3.20
LABEL org.opencontainers.image.source="https://github.com/Su1ph3r/caminus"
LABEL org.opencontainers.image.description="Multi-platform CI/CD pipeline attack-surface scanner"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /usr/local/bin/caminus /usr/local/bin/caminus
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Default entrypoint is the CLI itself; the GitHub Action overrides it.
ENTRYPOINT ["/usr/local/bin/caminus"]
