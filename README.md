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
│   ├── revpro/                # v1 bash plugin (Go rewrite pending)
│   │   ├── plugin.json        # type: "script"
│   │   ├── revpro.sh
│   │   └── template/...
│   └── ...
├── scripts/
│   ├── build-registry.sh      # Regenerates registry.json from manifests
│   └── build-bundles.sh       # Compiles Go plugins, packs all to releases/*.tar.gz
└── .github/workflows/
    └── validate.yml           # CI: validates + builds + releases per (linux × amd64/arm64)
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
| prjkt | script (bash) | ⚠ v1 — Go rewrite pending |
| revpro | script (bash) | ⚠ v1 — Go rewrite pending |

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
2. `bash scripts/build-registry.sh` to refresh the index.
3. Open a PR. CI validates the manifest, runs `go vet` + `go build`, packages the bundle.
4. On merge, a maintainer tags `<plugin>-v<version>` and the release workflow uploads the cross-compiled tarballs.

## Publishing & releasing

First push to GitHub:

```bash
bash scripts/push.sh              # creates the repo via gh if missing, pushes main
bash scripts/push.sh --tag-all    # also tags every plugin at its plugin.json version
```

Single-plugin release:

```bash
git tag reg-v2.0.0
git push origin reg-v2.0.0
```

The release job in `.github/workflows/validate.yml` cross-compiles every plugin for `linux/amd64` and `linux/arm64` and uploads the tarballs to the GitHub Release.
