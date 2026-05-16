# cmnds-registry

Official plugin registry for [CMNDS](https://github.com/maskalix/cmnds) v2+.

The `cmnds` binary fetches `registry.json` from this repo to discover available plugins. Each plugin lives in its own folder under `plugins/` and is shipped as a `.tar.gz` bundle through GitHub Releases.

## Repository layout

```
cmnds-registry/
├── registry.json              # Auto-generated index (do not edit by hand)
├── plugins/
│   ├── a/
│   │   ├── plugin.json        # Manifest (see PLUGIN_SCHEMA.md in cmnds repo)
│   │   └── a.sh               # Entry point
│   ├── revpro/
│   │   ├── plugin.json
│   │   ├── revpro.sh
│   │   └── template/...       # Supporting files
│   └── ...
├── scripts/
│   ├── build-registry.sh      # Rebuilds registry.json from manifests
│   └── build-bundles.sh       # Packs each plugin into releases/*.tar.gz
└── .github/workflows/
    └── validate.yml           # CI: validates manifests + publishes releases
```

## Installing a plugin (end user)

```bash
cmnds search                   # List available plugins from this registry
cmnds download <plugin>        # Pull and install
cmnds enable <plugin>          # Activate (creates /usr/local/bin/<plugin> symlink)
<plugin> [args]                # Use it
```

## Using a custom registry

Set the `CMNDS_REGISTRY_URL` environment variable to point at a fork:

```bash
export CMNDS_REGISTRY_URL=https://raw.githubusercontent.com/youruser/your-fork/main/registry.json
cmnds search
```

## Adding a plugin (contributor)

See `CONTRIBUTING.md` for the full workflow. Short version:

1. Create `plugins/<your-plugin>/plugin.json` and `<your-plugin>.sh`.
2. Run `bash scripts/build-registry.sh` to refresh the index.
3. Open a PR. CI validates the manifest and shellchecks your script.
4. On merge, a maintainer tags `<plugin>-v<version>` and the release workflow publishes the `.tar.gz`.

## Releasing

```bash
# Trigger a release for a single plugin
git tag a-v1.0.1
git push origin a-v1.0.1
```

The `release` job in `.github/workflows/validate.yml` rebuilds all bundles and uploads them to the tagged release.
