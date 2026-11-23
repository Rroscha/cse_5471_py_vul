---
name: vul-scan
description: Scan a Python web project (Flask/Django/FastAPI, etc.) for vulnerabilities with CodeQL. Reads the project's docs to build a threat model, identifies project-specific sources/sinks/sanitizers, generates custom CodeQL taint queries, runs them, and writes one Markdown file per finding. Use when asked to scan a Python web project for vulnerabilities.
argument-hint: <target-path> [--types <slug,...>] [--out <name>]
---

# vul-scan: CodeQL + LLM vulnerability scan for Python web projects

Arguments: `$ARGUMENTS`

## Arguments

| Argument | Required | Meaning | Default |
|---|---|---|---|
| `<target-path>` | yes | Python web project to scan | — |
| `--types` | no | Comma-separated vulnerability types to scan | all types below |
| `--out` | no | Name used for the output directory | basename of `<target-path>` |

Vulnerability types (slugs):

| Slug | Built-in CodeQL module to extend (`import semmle.python.security.dataflow.<File>`) |
|---|---|
| `sql_injection` | `SqlInjectionCustomizations` → `SqlInjection` |
| `command_injection` | `CommandInjectionCustomizations` → `CommandInjection` |
| `code_injection` | `CodeInjectionCustomizations` → `CodeInjection` |
| `path_traversal` | `PathInjectionCustomizations` → `PathInjection` |
| `unsafe_deserialization` | `UnsafeDeserializationCustomizations` → `UnsafeDeserialization` |
| `ssrf` | `ServerSideRequestForgeryCustomizations` → `ServerSideRequestForgery` |
| `xss` | `ReflectedXSSCustomizations` → `ReflectedXss` |
| `template_injection` | `TemplateInjectionCustomizations` → `TemplateInjection` |
| `open_redirect` | `UrlRedirectCustomizations` → `UrlRedirect` |

## Step 0: Setup

1. CodeQL is project-local (see the `codeql` skill). If `<repo>/.claude/skills/codeql/codeql/codeql` does not exist, stop and tell the user to install it.
2. Shell state does not persist between Bash calls. Prefix **every** CodeQL command with:
   ```bash
   export PATH="$(git rev-parse --show-toplevel)/.claude/skills/codeql/codeql:$PATH"
   ```
3. Never let CodeQL write outside the project. Pass these two options to **every** `codeql` command:
   ```
   --common-caches=<repo>/runs/.codeql-cache  "-J=-Djava.io.tmpdir=$TMPDIR"
   ```
   Without them CodeQL tries to create `~/.codeql` and use `/tmp`.
4. Create the run directory with a timestamp (never overwrite an earlier run):
   ```
   RUN=<repo>/runs/<name>-$(date +%Y%m%d-%H%M%S)
   ```

## Step 1: Threat model → `$RUN/threat_model.md`

Read the project's documentation first: `README`, `docs/`, example configs, deployment notes. Then write:

- **Framework**: Flask / Django / FastAPI / other. If the project is not a web application, stop and tell the user.
- **Public interface**: every route / API endpoint with its HTTP method, handler (`file:line`), and whether it requires authentication.
- **Attackers**: e.g. unauthenticated user, authenticated user, admin; which endpoints each can reach.
- **Trusted inputs**: inputs that are not attacker-controlled under this threat model (admin-only settings, local server files, environment config).

## Step 2: CodeQL database → `$RUN/db/`

Write `$RUN/codeql-config.yml` to exclude non-production code:

```yaml
paths-ignore:
  - tests
  - test
  - venv
  - .venv
  - "**/migrations"
  - "**/site-packages"
```

```bash
codeql database create $RUN/db --language=python --source-root=<target> \
  --codescanning-config=$RUN/codeql-config.yml --overwrite <common options>
```

## Step 3: Sources, sinks, sanitizers → `$RUN/spec.md`

Only for the requested `--types`. Focus on what CodeQL's built-in models miss: the project's own functions and third-party libraries.

- **Sources**: start from the public interface in `threat_model.md`. Request parameters, forms, JSON bodies, headers, cookies, uploaded files, and project helpers that return them (e.g. a custom `get_param(name)`).
- **Sinks**: grep for dangerous calls (`execute`, `subprocess`, `os.system`, `eval`, `exec`, `open`, `send_file`, `pickle`, `yaml.load`, `requests`, `urlopen`, `render_template_string`, `Markup`, `redirect`, …), then follow the call graph to find project wrappers around them (e.g. a custom `run_sql(q)`).
- **Sanitizers**: project functions that validate or escape data for a specific vulnerability type (e.g. a custom `validate_filename()`).
- **Taint steps**: functions through which taint should propagate but CodeQL might not model.

Rules:

- Every entry has `file:line`, the vulnerability type it applies to, and a one-line reason.
- Be specific. Never mark broad sets (e.g. "all function parameters") as sources or sinks.
- Do not try to read the whole project: go from entry points and grep hits, and follow calls from there.

## Step 4: Queries → `$RUN/queries/`

`$RUN/queries/qlpack.yml`:

```yaml
name: pyvul/queries
version: 0.0.1
dependencies:
  codeql/python-all: "*"
```

One `<slug>.ql` per requested type. Always **extend** the built-in module with `or`, never replace it, so the custom query finds at least what CodeQL already finds. Example for `sql_injection`:

```ql
/**
 * @name Project-specific SQL injection
 * @kind path-problem
 * @problem.severity error
 * @id pyvul/sql-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.SqlInjectionCustomizations

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof SqlInjection::Source
    // or <project-specific sources from spec.md>
  }

  predicate isSink(DataFlow::Node n) {
    n instanceof SqlInjection::Sink
    or
    // project-specific sink from spec.md: first argument of run_sql(...)
    exists(DataFlow::CallCfgNode c |
      c.getFunction().asCfgNode().(NameNode).getId() = "run_sql" and
      n = c.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    n instanceof SqlInjection::Sanitizer
    // or <project-specific sanitizers from spec.md>
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    none() // or <project-specific taint steps from spec.md>
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from $@ reaches this sink.", source.getNode(), "this source"
```

- `@id` must use hyphens: `pyvul/<slug with _ replaced by ->`.
- For third-party library APIs, prefer API graphs, e.g. `n = API::moduleImport("lib").getMember("run").getACall().getArg(0)`.
- Compile each query: `codeql query compile $RUN/queries/<slug>.ql <common options>`. On errors, fix and recompile, **at most 5 attempts per query**. If it still fails, delete that `.ql`, and record the slug and the last error for `scan.md`.

## Step 5: Scan → `$RUN/custom.sarif`

```bash
codeql database analyze $RUN/db $RUN/queries --format=sarif-latest \
  --output=$RUN/custom.sarif <common options>
```

## Step 6: Findings → `$RUN/findings/` and `$RUN/scan.md`

Read `custom.sarif` (`runs[0].results[]`; each result's path is in `codeFlows[0].threadFlows[0].locations[]`). Drop consecutive duplicate path steps. If several results share the same source and sink, keep one.

Write one file per finding: `$RUN/findings/F<NNN>-<slug>.md`, numbered from `F001`, sorted by type then by sink file and line. Format:

````markdown
---
id: F001
category: sql_injection
severity: high
rule: pyvul/sql-injection
source: app/views.py:42
sink: app/db.py:88
---

# F001: SQL Injection: `app/db.py:88`

* Severity: High
* Description: `q` from `request.args` in the public `/search` endpoint (unauthenticated) flows through `build_query()` into `cursor.execute()` without parameterization.
* Recommendation: Use parameterized queries: `cursor.execute("... WHERE name=%s", (q,))`.

## Data flow

1. **Source** `app/views.py:42`
   ```python
   q = request.args["q"]
   ```
2. `app/utils.py:15`
   ```python
   sql = build_query(q)
   ```
3. **Sink** `app/db.py:88`
   ```python
   cursor.execute(sql)
   ```
````

- The title location is the sink.
- Each data-flow step shows the actual code line from the target project.
- Severity, using `threat_model.md` (e.g. whether the endpoint needs authentication):
  - **High**: directly exploitable, leads to RCE, data breach, or authentication bypass.
  - **Medium**: needs specific conditions but has significant impact.
  - **Low**: defense-in-depth or low impact.

Then write `$RUN/scan.md`:

1. Target, run directory, requested types.
2. Table of findings: ID, category, severity, sink, link to the finding file.
3. Count per type.
4. Queries skipped because they failed to compile, with the last error.

Finally, give the user a short summary and the path of `scan.md`.
