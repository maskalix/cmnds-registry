# Contributing to cmnds-registry

## Plugin requirements

Every plugin folder under `plugins/` must contain:

1. **`plugin.json`** — manifest matching the schema in [maskalix/cmnds PLUGIN_SCHEMA.md](https://github.com/maskalix/cmnds/blob/main/PLUGIN_SCHEMA.md).
2. **An entry-point script** named after `plugin.json:entry_point`.
3. (Optional) Any supporting files, templates, configs.

Required fields in `plugin.json`:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Must match the folder name and the `registry.json` entry. |
| `version` | string | Semver (`MAJOR.MINOR.PATCH`). |
| `description` | string | One-line summary shown in `cmnds search`. |
| `type` | string | `"script"` for bash, `"binary"` for compiled. |
| `entry_point` | string | Filename of the executable inside the plugin folder. |
| `category` | string | `docker`, `files`, `system`, `ssh`, `network`, `security`, `revpro`, etc. |

## Writing the script

Start from the template in the main repo (`PLUGIN_TEMPLATE.sh`). Important runtime guarantees provided by the cmnds host:

- Script is executed via `bash <entry_point> $args`.
- Working directory is set to the plugin folder, so relative paths (templates, configs) resolve correctly.
- `PATH` is prepended with every enabled plugin's folder, so you can invoke other plugins directly by name (e.g. `cmnds-config read REVPRO`).
- The plugin can read shared configuration via `cmnds config read VAR_NAME`.

Recommended shebang: `#!/usr/bin/env bash` with `set -euo pipefail`.

## Submitting a plugin

1. Fork this repo.
2. `mkdir plugins/<your-plugin>` and add `plugin.json` + your script.
3. Run `bash scripts/build-registry.sh` to refresh `registry.json` (or let CI do it on PR).
4. Open a PR. CI runs:
   - JSON validity on `registry.json` and every `plugin.json`.
   - Folder name matches `plugin.json.name`.
   - Entry point exists.
   - Plugin is listed in `registry.json`.
   - Shellcheck on every `.sh` (warnings tolerated, errors block merge).
5. On merge, a maintainer creates a tag `<name>-v<version>` and the release workflow uploads `releases/<name>-<version>.tar.gz` to the GitHub Release.

## Versioning

- Bump `version` in `plugin.json` for every user-visible change.
- Use semver: breaking change → MAJOR, new feature → MINOR, fix → PATCH.
- Tag format: `<name>-v<version>` (e.g. `revpro-v1.2.0`).

## Local testing

```bash
# From the main cmnds repo:
export CMNDS_REGISTRY_URL=file:///path/to/your/cmnds-registry/registry.json   # if your cmnds build supports file://; otherwise serve locally
# Or temporarily point at your fork:
export CMNDS_REGISTRY_URL=https://raw.githubusercontent.com/<you>/cmnds-registry/<branch>/registry.json

cmnds search
cmnds download <your-plugin>
cmnds enable <your-plugin>
<your-plugin> --help
```

## Removing or renaming a plugin

- Delete the folder under `plugins/`.
- Regenerate `registry.json`.
- Bump a date-stamped tag (e.g. `registry-2026-05-16`) to invalidate any caches.
- Note the removal in the PR description so users can be warned.
