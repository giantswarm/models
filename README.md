# models

Curated model images for the Giant Swarm agent platform: Hugging Face checkpoints built, signed and
published as OCI modelcars to `gsoci.azurecr.io/giantswarm/models/<name>:<revision>`.

A serving preset of the agent platform references such an image as `storageUri: oci://…`; KServe's
modelcar path pulls it onto the GPU node like any container image, so a warm node starts a 100 GiB
model from local disk, without a download and without a shared cache volume. The weights are signed
with cosign under this pipeline's CircleCI identity, and the platform's Kyverno policy admits only images
that carry such a signature.

## Adding a model

One file under [`models/`](models/) per image:

```yaml
apiVersion: models.giantswarm.io/v1alpha1
kind: ModelImage
metadata:
  name: qwen3-8-flash-next-nvfp4          # the image path suffix and the preset name
spec:
  huggingFace:
    repository: local-inference-lab/Qwen3.8-Flash-Next-NVFP4
    revision: 7c4f1bc1a2d6847e0cbc01ac6b823f00251de8dd   # full commit hash
  description: One sentence about the model, for the image annotations.
  license: LicenseRef-Qwen                # SPDX identifier where one exists
  # base: gsoci.azurecr.io/giantswarm/busybox:1.38.0     # the default
  # exclude: [README.md, .gitattributes, "*.png", ...]  # the default
```

`make test` and `go run . validate` check the file; CI's `validate-models` job resolves it on the Hub on
every pull request. On merge to `main`, `publish-models` builds the image, signs it and attests its SBOM.
Renovate follows the checkpoint's default branch on the Hub and opens the revision bump; merging it
publishes the next image under the new tag. The tag is the first twelve characters of the revision, so
a preset pins one exact checkpoint.

## What an image is

- A two-platform index (`linux/amd64`, `linux/arm64`) whose manifests share **one uncompressed tar
  layer** with the checkpoint's files under `/models` — safetensors do not compress, and a node's pull
  is a copy instead of a decompression. Only the base layer, a busybox shell for KServe's modelcar
  sidecar, differs per platform.
- Every file is hashed as it streams; an LFS file whose bytes differ from the Hub's record fails the
  build. The hashes go into an SPDX document attested on the image (`cosign verify-attestation --type
  spdxjson`); the index carries the checkpoint's repository and revision as annotations.
- The image is signed keyless with cosign under the pipeline's CircleCI OIDC identity (issuer
  `https://oidc.circleci.com`, subject `https://circleci.com/api/v2/projects/<project>/pipeline-definitions/<definition>`),
  as a Sigstore bundle referrer — the same shape as every image the architect orb publishes.
- A tag is never re-pushed with other content: a run finds the tag holding its checkpoint and moves
  on; a tag holding another checkpoint fails the run.

## How the build fits a hosted CI executor

A checkpoint is 25–125 GiB; a build that downloads it and then packages it needs twice that on disk.
This pipeline needs none: each file streams from the Hub through the tar writer straight into the
registry's chunked blob upload, two 256 MiB chunks in memory at a time, resuming a dropped connection
on either side from the last byte. That is why `publish-models` runs on the ordinary Docker executor
with the `architect` image.

## Verifying an image

```bash
cosign verify \
  --certificate-oidc-issuer-regexp '^https://oidc\.circleci\.com' \
  --certificate-identity-regexp '^https://circleci\.com/api/v2/projects/[a-f0-9-]+/pipeline-definitions/[a-f0-9-]+$' \
  gsoci.azurecr.io/giantswarm/models/qwen3-8-flash-next-nvfp4:7c4f1bc1a2d6

cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer-regexp '^https://oidc\.circleci\.com' \
  --certificate-identity-regexp '^https://circleci\.com/api/v2/projects/[a-f0-9-]+/pipeline-definitions/[a-f0-9-]+$' \
  gsoci.azurecr.io/giantswarm/models/qwen3-8-flash-next-nvfp4:7c4f1bc1a2d6 | jq -r .payload | base64 -d | jq .predicate.files
```

## Local use

```bash
go run . validate                                            # every specification resolves
MODELS_REGISTRY_USERNAME=… MODELS_REGISTRY_PASSWORD=… \
  go run . publish --spec models/<name>.yaml --registry <host>/<path>   # build and push one image
```

`publish` never writes the weights to disk; it needs network, two vCPUs and about a gigabyte of memory.
