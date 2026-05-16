# Contributing to cmnds-registry

## Choosing a plugin type

| Type | Use when | Avoid when |
|---|---|---|
| **`binary` (Go)** | Default. New plugins, anything non-trivial. | Almost never — Go always works. |
| **`script` (bash)** | Two-line shell wrappers where Go would be more code than logic. | Anything stateful, anything with parsing, anything > 30 lines. |
| **`python`** | Heavy templating, data processing where stdlib really helps. | Anything Go can do — Python is heavy. |

## Plugin manifest (`plugin.json`)

Required fields:

```json
{
  "name": "myplugin",
  "version": "1.0.0",
  "description": "One-line summary",
  "author": "Your Name",
  "type": "binary",
  "entry_point": "myplugin",
  "category": "system",
  "dependencies": {
    "apt": [],
    "plugins": []
  },
  "help": {
    "usage": "myplugin <command>",
    "description": "Detailed description",
    "options": [{"flag": "-h, --help", "description": "Show help"}],
    "examples": [{"command": "myplugin foo", "description": "Do foo"}]
  }
}
```

Field rules:
- `name` must match the folder name and the `registry.json` entry.
- `entry_point` for `binary` is the **compiled** binary name (no extension); for `script`/`python` it's the source filename.
- `category` — pick one: `docker`, `files`, `system`, `ssh`, `network`, `security`, `revpro`, etc.

## Writing a Go plugin

Layout:

```
plugins/myplugin/
├── plugin.json
├── main.go
└── go.mod
```

Minimal `go.mod`:

```
module myplugin

go 1.24
```

Minimal `main.go`:

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 || os.Args[1] == "-h" {
        fmt.Println("Usage: myplugin <command>")
        return
    }
    fmt.Println("hello from myplugin:", os.Args[1])
}
```

Runtime guarantees the cmnds host provides at invocation time:
- Working directory is the plugin folder.
- `PATH` is prepended with every enabled plugin's folder — call other plugins by name (`exec.LookPath("revpro")` works).
- Shared config via `exec.Command("cmnds", "config", "read", "VARNAME")`.

Keep binaries small and CGO-free:

```bash
go build -trimpath -ldflags="-s -w" -o myplugin .
```

## Writing a bash plugin (when really needed)

Start with `set -euo pipefail`. Read shared config with `cmnds config read NAME`. Print colored prefixes using ANSI escapes. Keep the script focused — if it grows past 50 lines, port it to Go.

## Submitting

1. Fork this repo.
2. `mkdir plugins/<your-plugin>`, add files.
3. `bash scripts/build-registry.sh` to refresh `registry.json`.
4. Test locally:
   ```bash
   cd plugins/<your-plugin> && go build -o <name> . && ./<name> ...
   ```
5. Open a PR. CI runs:
   - `registry.json` schema check.
   - Every `plugin.json` has the required fields.
   - Folder name matches `plugin.json.name`.
   - Plugin listed in `registry.json`.
   - For Go plugins: `go vet` + `go build`.
   - For bash plugins: shellcheck warnings (non-fatal).
6. On merge, a maintainer tags `<name>-v<version>`. The release job cross-compiles for linux/amd64 and linux/arm64 and uploads the tarballs.

## Versioning

Semver. Bump for every user-visible change. Tag format: `<name>-v<version>` (e.g. `reg-v2.0.0`).

## Local testing against the real cmnds binary

```bash
# Build a temporary registry index for your work-in-progress branch:
export CMNDS_REGISTRY_URL=https://raw.githubusercontent.com/<you>/cmnds-registry/<branch>/registry.json
cmnds search
cmnds download <your-plugin>
cmnds enable <your-plugin>
<your-plugin> --help
```

## Removing or renaming a plugin

- Delete the folder under `plugins/`.
- Rebuild `registry.json`.
- Commit + push. Existing users won't auto-uninstall; document removal in PR description and CHANGELOG.
