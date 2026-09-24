# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Added

- A `ModelImage` can declare `extraFiles`: files the checkpoint's repository does not carry, each by
  HTTPS URL, `sha256` and path under `/models`. They are streamed and hashed like the checkpoint's files
  into a layer of their own, a wrong hash fails the build (and `validate`, so the pull request), and the
  SPDX document lists each as a package with its URL. Such an image is tagged
  `<revision[:12]>-<extra files digest[:8]>`; an image without extra files keeps its tag.
- An image with extra files references the layers of the checkpoint's published image when they are the
  layers the build would stream (the same files in layers of the same tar sizes), and streams only the
  extra files.
- `gpt-oss-20b` and `gpt-oss-120b` carry the `o200k_base` and `cl100k_base` tiktoken encodings under
  `/models/tiktoken/`, so the harmony renderer loads them with `TIKTOKEN_ENCODINGS_BASE=/mnt/models/tiktoken`
  instead of downloading them at the first request: new tags `6cee5e81ee83-7abb6426` and
  `b5c939de8f75-7abb6426`.

- The first batch of the September 2026 open-weight line-up, eight model images: `qwen3-8-27b-nvfp4`,
  `qwen3-6-35b-a3b-fp8`, `gpt-oss-20b` (without the repository's `original/` and `metal/` copies),
  `gemma-4-12b-qat-w4a16`, `qwen3-5-9b-fp8`, `qwen3-5-4b`, `gemma-4-31b-fp8` and `muse-glimmer-30b-fp8`.
- The second batch of the September 2026 open-weight line-up, two model images: `gpt-oss-120b`
  (without the repository's `original/` and `metal/` copies) and `mistral-small-4-nvfp4` (Mistral's own
  file format: consolidated safetensors, `params.json`, the tekken tokenizer).



[Unreleased]: https://github.com/giantswarm/models/tree/main
