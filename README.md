# cmnds-registry

Official plugin registry for [CMNDS](https://github.com/maskalix/cmnds-v2) v2+.

The `cmnds` binary fetches `registry.json` from this repo to discover plugins. Each plugin lives in its own folder under `plugins/` and is shipped as a `.tar.gz` bundle through GitHub Releases.

**Plugins are Go-first.** Bash is allowed but discouraged — Go gives single-binary distribution, type safety, and proper testing. Python is supported but reserved for cases where it's clearly better than Go (rare).

## Repository layout

```
cmnds-registry/
├── registry.json              # Auto-generated index (do not edit by hand)
├── plugins/
│   ├── reg/                   # Go plugin
│   │   ├── plugin.json        # Manifest (type: "binary")
│   │   ├── main.go            # Source
│   │   └── go.mod
│   ├── revpro/                # Go plugin with embedded nginx templates
│   │   ├── plugin.json        # type: "binary"
│   │   ├── main.go
│   │   ├── go.mod
│   │   └── templates/...      # go:embed'd into the binary
│   ├── prjkt/                 # v1 bash plugin (Go rewrite pending)
│   │   ├── plugin.json        # type: "script"
│   │   └── prjkt.sh
│   └── ...
└── .github/workflows/
    └── validate.yml           # CI: validates on push/PR; builds + publishes a
                               #     release asset on each <name>-v<version> tag
```

## Plugin types

| Type | When to use | `entry_point` |
|---|---|---|
| `binary` | **Default for new plugins.** Compile a Go (or other) binary. | filename of the compiled binary (e.g. `reg`) |
| `script` | Legacy bash. Acceptable for trivial wrappers; flagged for migration. | `*.sh` filename |
| `python` | Genuine cases needing Python's stdlib/templating. Avoid otherwise — Python is heavy. | `*.py` filename |

## Plugin status

| Plugin | Type | Status |
|---|---|---|
| cpc | binary (Go) | ✅ |
| perf | binary (Go) | ✅ |
| rcmount | binary (Go) | ✅ |
| rec | binary (Go) | ✅ |
| reg | binary (Go) | ✅ |
| remount | binary (Go) | ✅ |
| smartchck | binary (Go) | ✅ |
| ssh-init | binary (Go) | ✅ |
| system-update | binary (Go) | ✅ |
| revpro | binary (Go) | ✅ |
| prjkt | script (bash) | ⚠ v1 — Go rewrite pending |

## Installing a plugin (end user)

```bash
cmnds                          # opens the TUI — browse + install + enable visually
# or, on the CLI:
cmnds search
cmnds download <plugin>
cmnds enable <plugin>
<plugin> [args]                # standalone, no 'cmnds ' prefix needed
```

## Using a custom registry

```bash
export CMNDS_REGISTRY_URL=https://raw.githubusercontent.com/youruser/your-fork/main/registry.json
cmnds search
```

## Adding a plugin (contributor)

See `CONTRIBUTING.md`. Short version:

1. `mkdir plugins/<name>` with `plugin.json`, `main.go`, `go.mod`.
2. Add a matching entry to `registry.json` (name, version, description, category,
   and `download_url` of the form
   `https://github.com/maskalix/cmnds-registry/releases/download/<name>-v<version>/<name>-<version>.tar.gz`).
3. Open a PR. CI validates the manifest and runs `go vet` + `go build`.
4. On merge, a maintainer tags `<name>-v<version>` (below) and the release workflow publishes the bundle.

## Publishing & releasing

A release is cut **per plugin** by pushing a version tag. The `release` job in
`.github/workflows/validate.yml` fires on any `<name>-v<version>` tag, builds
that one plugin into `<name>-<version>.tar.gz` (binary plugins → a static
`linux/amd64` binary; script/python → all source files), and uploads it as the
tag's release asset — the exact URL `registry.json` points at.

```bash
git tag reg-v2.0.0
git push origin reg-v2.0.0          # → workflow publishes reg-2.0.0.tar.gz
```

To (re)release every plugin at its current `plugin.json` version:

```bash
for d in plugins/*/; do
  name=$(basename "$d"); ver=$(jq -r .version "$d/plugin.json")
  git tag "${name}-v${ver}" 2>/dev/null && echo "tagged ${name}-v${ver}"
done
git push origin --tags
```

> **Architecture note:** bundles are `linux/amd64` only — `registry.json` has a
> single `download_url` per plugin. Supporting arm64 would require per-arch URLs
> in the schema and arch-aware selection in the downloader.
