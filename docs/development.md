# Developing on models

The tool is one Go module: `main.go` is the `models` command, the packages under `internal/` do the work.

| Package | Responsibility |
|---|---|
| `internal/spec` | reads and validates the specification files under `models/` |
| `internal/hub` | the Hugging Face Hub: file list with sizes and LFS hashes, resumable file streams |
| `internal/modelcar` | the weights layer as a deterministic tar stream, the two-platform image and its publication |
| `internal/registry` | the resumable chunked blob upload (one PATCH per 256 MiB, resumed from the registry's offset) |
| `internal/sbom` | the SPDX document attested on every image |

```bash
make test            # unit tests, including a publication against an in-memory registry
make lint            # golangci-lint as CI runs it
go run . validate    # resolve every specification on the Hub
```

A real end-to-end run needs a registry and a checkpoint; a small public one against a local registry:

```bash
docker run -d --rm -p 127.0.0.1:5000:5000 registry:3
go run . publish --dir <dir with one spec> --registry localhost:5000/giantswarm/models --chunk-mib 1
crane manifest localhost:5000/giantswarm/models/<name>:<tag> | jq .
```

The weights never touch disk, so the run needs no scratch space; the base image is pulled from the
registry named in the specification (the default lives on gsoci and is public).

## CI

`.circleci/workflows.yml` is generated (devctl, via giantswarm/github's align-files) and carries the
`go-build` job; `.circleci/custom.yml` is this repository's and carries `validate-models` (every branch)
and `publish-models` (main only, after `go-build` and `validate-models`). Signing uses the architect orb's
`cosign-sign-verify` command, so the identity is the same as for every other Giant Swarm image.
