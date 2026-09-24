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
  # extraFiles:                           # files the checkpoint's repository does not carry
  #   - url: https://openaipublic.blob.core.windows.net/encodings/o200k_base.tiktoken
  #     sha256: 446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d
  #     path: tiktoken/o200k_base.tiktoken   # under /models
```

`make test` and `go run . validate` check the file; CI's `validate-models` job resolves it on the Hub and
fetches every extra file against its `sha256` on every pull request. On merge to `main`, `publish-models` builds the image, signs it and attests its SBOM.
Renovate follows the checkpoint's default branch on the Hub and opens the revision bump; merging it
publishes the next image under the new tag. The tag is the first twelve characters of the revision, so
a preset pins one exact checkpoint. An image with extra files is tagged `<revision[:12]>-<extra[:8]>`,
where `extra` is the hex sha256 of one `<path> <sha256>\n` line per extra file, sorted, concatenated:
adding, moving or re-pinning an extra file publishes a new tag, and a mirror's URL changes nothing.

## What an image is

- A two-platform index (`linux/amd64`, `linux/arm64`) whose manifests share the **uncompressed tar
  layers** with the checkpoint's files under `/models` — safetensors do not compress, and a node's
  pull is a copy instead of a decompression. The checkpoint is cut into as few layers as 8 GiB per layer
  allows (files whole, in path order; `--layer-gib` changes the limit): a registry finalizes a blob in
  time proportional to its size and a node pulls layers in parallel. Only the base layer, a busybox
  shell for KServe's modelcar sidecar, differs per platform.
- Extra files (`spec.extraFiles`: a runtime's files the checkpoint's repository does not carry, such as
  the tiktoken encodings the gpt-oss harmony renderer reads) follow in a layer of their own, so the
  checkpoint's layers are the same blobs with and without them. Each is fetched from its HTTPS URL
  and must not land on a checkpoint file.
- Every file is hashed as it streams; an LFS file whose bytes differ from the Hub's record, or an extra
  file whose bytes differ from its pinned `sha256`, fails the build. The hashes go into an SPDX document
  attested on the image (`cosign verify-attestation --type spdxjson`), an extra file as a package of its
  own with its URL; the index carries the checkpoint's repository and revision as annotations, and the
  extra files' digest as `io.giantswarm.models.extra-files`.
- The image is signed keyless with cosign under the pipeline's CircleCI OIDC identity (issuer
  `https://oidc.circleci.com`, subject `https://circleci.com/api/v2/projects/<project>/pipeline-definitions/<definition>`),
  as a Sigstore bundle referrer — the same shape as every image the architect orb publishes.
- A tag is never re-pushed with other content: a run finds the tag holding its checkpoint and moves on;
  a tag holding another checkpoint or other extra files fails the run. What a run does repair is a
  missing signature or attestation: an image found already published is listed for signing with its SBOM
  rebuilt from the Hub's record, and the job signs and attests only what does not verify yet.

## How the build fits a hosted CI executor

A checkpoint is 25–125 GiB; a build that downloads it and then packages it needs twice that on disk.
This pipeline needs none: each file streams from the Hub through the tar writer straight into the
registry's chunked blob upload, two 256 MiB chunks in memory at a time, resuming a dropped connection
on either side from the last byte. That is why `publish-models` runs on the ordinary Docker executor
with the `architect` image.

After a layer's last byte the registry finalizes the blob — it hashes what it holds, which takes
minutes for a large blob — and its gateway may give up on the commit request before that (Azure
Container Registry answers 504 after eight minutes, which one 106 GB layer did not fit; hence the 8 GiB
limit) while the registry keeps working. The tool names each layer's digest before its commit, polls
for the blob by that digest after an unconfirmed commit, and sends the commit again only while the
upload still exists with every byte. A layer is the same bytes on every build of a revision, so a blob
an earlier run left committed is recognised at commit time and never committed twice.

An image with extra files streams only them when the checkpoint's own image (the tag without the
suffix) is published: the tool computes each layer's tar size from the file list without reading a byte,
and when that image holds the same files in layers of exactly those sizes, it references its blobs
instead of streaming the checkpoint again. Otherwise the checkpoint streams as for any image; either
way the result is the same image.

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
