package shims

import _ "embed"

//go:embed node/go-secrets-preload.js
var NodeShimContent string

//go:embed python/go_secrets_preload.py
var PythonShimContent string

