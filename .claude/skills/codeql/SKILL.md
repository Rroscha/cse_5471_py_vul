---
name: codeql
description: Install (latest CodeQL bundle) or locate the project-local CodeQL CLI in tools/codeql/ and put it on PATH. Use before running any codeql command, or when codeql is missing or needs to be updated.
---

# CodeQL install (project-local)

CodeQL lives in the repo's `tools/` directory, not globally:

```
<repo>/tools/
└── codeql/            ← CodeQL bundle
    ├── codeql         ← executable
    ├── python/
    ├── qlpacks/
    └── ...
```

`<repo>` is the git root: `git rev-parse --show-toplevel`.

## 1. Check whether it is already installed

```bash
REPO="$(git rev-parse --show-toplevel)"
"$REPO/tools/codeql/codeql" version
```

If this prints a version, skip to step 5. Reinstall only if the user asks to update.

## 2. Download the latest CodeQL bundle

The bundle includes the CodeQL CLI and the standard query packs (including Python), so no separate pack download is needed.

```bash
REPO="$(git rev-parse --show-toplevel)"
mkdir -p "$REPO/tools"
curl -L -o "$REPO/tools/codeql-bundle.tar.gz" \
  https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
```

## 3. Extract and remove the archive

The archive's top-level directory is `codeql/`, so extracting into `tools/` creates `tools/codeql/`.

```bash
REPO="$(git rev-parse --show-toplevel)"
tar -xzf "$REPO/tools/codeql-bundle.tar.gz" -C "$REPO/tools/"
rm "$REPO/tools/codeql-bundle.tar.gz"
```

When updating, first delete `tools/codeql/`, then run steps 2–3.

## 4. Verify

```bash
REPO="$(git rev-parse --show-toplevel)"
"$REPO/tools/codeql/codeql" version
"$REPO/tools/codeql/codeql" resolve languages
```

The language list must include `python`.

## 5. Put CodeQL on PATH

Shell state does not persist between commands, so prefix each command that uses CodeQL:

```bash
export PATH="$(git rev-parse --show-toplevel)/tools/codeql:$PATH"
```
