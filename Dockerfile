# Backend image: multi-stage Go build → distroless-ish minimal runtime.
# Produces two binaries (server, eval) so `docker compose run backend /app/eval`
# scores the detectors against ground truth in the same image.
FROM golang:1.22-bookworm AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/seed   ./cmd/seed \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/eval   ./cmd/eval

# Runtime: needs the Go toolchain available for the rule-generation compile
# check (internal/rulegen shells out to `go build` in an isolated module).
FROM golang:1.22-bookworm AS runtime
WORKDIR /app
ENV GOFLAGS=-mod=mod GOTOOLCHAIN=local
COPY --from=build /out/server /app/server
COPY --from=build /out/seed   /app/seed
COPY --from=build /out/eval   /app/eval
# Pre-warm the module cache used by rulegen's throwaway builds.
RUN useradd -m app && chown -R app /app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/server"]
