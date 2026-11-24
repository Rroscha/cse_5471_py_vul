---
name: vul-scan
description: Scan a Python web project (Flask/Django/FastAPI, etc.) for vulnerabilities with CodeQL. Recons the whole repository, builds a threat model, identifies project-specific sources/sinks/sanitizers for every applicable vulnerability type, generates custom CodeQL taint queries, runs them, writes one Markdown file per finding, then verifies each finding as a true or false positive. Use when asked to scan a Python web project for vulnerabilities.
argument-hint: <target-path> [--types <slug,...>] [--out <name>]
---

# vul-scan: CodeQL + LLM vulnerability scan for Python web projects

Arguments: `$ARGUMENTS`

## Arguments

| Argument | Required | Meaning | Default |
|---|---|---|---|
| `<target-path>` | yes | Python web project to scan | — |
| `--types` | no | Comma-separated vulnerability type slugs to restrict the scan to | every applicable type (Step 4) |
| `--out` | no | Name used for the output directory | basename of `<target-path>` |

A vulnerability type slug is the snake_case name of the vulnerability class, e.g. `sql_injection`, `command_injection`, `code_injection`, `path_traversal`, `tar_slip`, `xxe`, `ssrf`, `xss`, `template_injection`, `open_redirect`, `config_injection`. There is no fixed list.

## Step 0: Setup

1. CodeQL is project-local (see the `codeql` skill). If `<repo>/tools/codeql/codeql` does not exist, stop and tell the user to install it.
2. Shell state does not persist between Bash calls. Prefix **every** CodeQL command with:
   ```bash
   export PATH="$(git rev-parse --show-toplevel)/tools/codeql:$PATH"
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

## Step 1: Recon → `$RUN/recon.md`

Map the whole repository before modeling anything. Read the documentation first (`README`, `docs/`, example configs, deployment notes), then the code. Cover **every package**, not just the web layer.

- **Layout**: top-level packages, entry points (web app, API, CLI, daemons, background threads, listeners on other ports), and extension mechanisms (plugins, addons, hooks, scheduled jobs).
- **Frameworks and libraries**: web framework, database layer, template engine, HTTP clients, parsers (XML, YAML, archives), process execution helpers.
- **Roles and permissions**: authentication methods, roles, permission checks (decorators, allow/deny lists), and what each role may read or change.
- **Attacker-writable persistent state**: data a lower-privileged role can write that the system reads back later, e.g. config options, database fields, uploaded or synced files, user settings. For each, list where it is written (`file:line`), which role can write it, and where it is read back (`file:line`).
- **Dynamic dispatch**: places where user input selects the code to run, e.g. `getattr(obj, name)(...)`, RPC or "exposed method" registries, string-to-handler maps. List the entry point and the target methods reachable through it.
- **Existing security mechanisms**: the project's own sanitizers, validators, path/URL/host checks, admin-only lists. These become sanitizers in Step 4 and bypass candidates in Step 8.

## Step 2: Threat model → `$RUN/threat_model.md`

Based on `recon.md`:

- **Framework**: Flask / Django / FastAPI / other. If the project is not a web application, stop and tell the user.
- **Public interface**: every route / API endpoint with its HTTP method, handler (`file:line`), and required authentication or permission. Include endpoints reached through dynamic dispatch.
- **Attackers**: e.g. unauthenticated user, malicious web page in a user's browser, authenticated user with specific permissions, admin; which entry points each can reach.
- **Trusted inputs**: only data that no attacker role can write (e.g. admin-only settings, CLI flags, environment). Everything listed under "attacker-writable persistent state" in `recon.md` is untrusted for the roles that can write it.

## Step 3: CodeQL database → `$RUN/db/`

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

## Step 4: Vulnerability types, sources, sinks, sanitizers → `$RUN/spec.md`

### 4.1 Vulnerability types

List every vulnerability type that applies to this project, based on `recon.md` (e.g. LDAP injection only if LDAP is used, XXE if XML is parsed, tar/zip slip if archives are extracted, config injection if attacker-writable values are written into config or other persisted formats). Aim for as many types as apply. If `--types` is given, keep only those.

For each type, find out whether CodeQL has a built-in model. List the available modules from the bundle:

```bash
ls $(git rev-parse --show-toplevel)/tools/codeql/qlpacks/codeql/python-all/*/semmle/python/security/dataflow/*Customizations.qll
```

Each `<Name>Customizations.qll` defines a module with `Source`, `Sink` and `Sanitizer` classes (read the file to get the exact module name). Record in `spec.md`, per type: the slug, and the built-in module to extend, or "custom" if there is none.

Skip types that verification would always reject (see Step 8 B): ReDoS (`PolynomialReDoS`), `RegexInjection`, `LogInjection`, `XmlBomb`, and other denial-of-service classes.

### 4.2 Sources, sinks, sanitizers, taint steps

Focus on what CodeQL's built-in models miss: the project's own functions, third-party libraries, and indirect flows.

- **Sources**:
  1. Direct inputs: request parameters, forms, JSON bodies, headers, cookies, uploaded files, and project helpers that return them (e.g. a custom `get_param(name)`). Handler parameters filled by project decorators (e.g. a decorator that passes the JSON body as keyword arguments).
  2. Dynamic dispatch: parameters of every target method reachable through a dynamic-dispatch entry point in `recon.md`.
  3. Second-order: every place where attacker-writable persistent state from `recon.md` is read back (e.g. `config.get(...)` of an option a non-admin can set). Model these read sites as sources, or add a taint step from the write API to the read API.
- **Sinks**: grep the **whole repository** (including plugins, addons, and background code) for dangerous calls (`execute`, `subprocess`, `os.system`, `eval`, `exec`, `open`, `send_file`, `extractall`, `pickle`, `yaml.load`, XML parsers, `requests`, `urlopen`, `render_template_string`, `Markup`, `redirect`, writes to config or other persisted files, …), then follow the call graph to find project wrappers around them (e.g. a custom `run_sql(q)`).
- **Sanitizers**: project functions that validate or escape data for a specific vulnerability type (e.g. a custom `validate_filename()`).
- **Taint steps**: functions or storage through which taint should propagate but CodeQL might not model.

Rules:

- Every entry has `file:line`, the vulnerability type(s) it applies to, and a one-line reason.
- Be specific. Never mark broad sets (e.g. "all function parameters") as sources or sinks.
- Do not try to read the whole project line by line: go from the entry points, dynamic-dispatch targets, persistent-state read sites, and grep hits, and follow calls from there.
- **Coverage check**: every attacker-writable store and every dynamic-dispatch target in `recon.md` must appear in `spec.md`, either modeled or with a reason why not.

## Step 5: Queries → `$RUN/queries/`

`$RUN/queries/qlpack.yml`:

```yaml
name: pyvul/queries
version: 0.0.1
dependencies:
  codeql/python-all: "*"
```

Put project-specific sources, sinks, sanitizers and taint steps that several queries share into one library file, e.g. `$RUN/queries/ProjectModels.qll`, and import it from each query.

Write one `<slug>.ql` per type in `spec.md`.

**Type with a built-in module**: always **extend** the module with `or`, never replace it, so the query finds at least what CodeQL already finds. Example for `sql_injection`:

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
import ProjectModels

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof SqlInjection::Source
    or
    projectSource(n) // project-specific sources from spec.md
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
    projectTaintStep(a, b) // project-specific taint steps from spec.md
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from $@ reaches this sink.", source.getNode(), "this source"
```

**Custom type** (no built-in module): same structure without the module import. Sources are `RemoteFlowSource` (`import semmle.python.dataflow.new.RemoteFlowSources`) plus the project-specific sources; sinks, sanitizers and taint steps come entirely from `spec.md`.

- `@id` must use hyphens: `pyvul/<slug with _ replaced by ->`.
- For third-party library APIs, prefer API graphs, e.g. `n = API::moduleImport("lib").getMember("run").getACall().getArg(0)`.
- Compile all queries: `codeql query compile $RUN/queries <common options>`. On errors, fix and recompile, **at most 5 attempts per query**. If one still fails, delete that `.ql`, and record the slug and the last error for `scan.md`.

## Step 6: Scan → `$RUN/custom.sarif`

```bash
codeql database analyze $RUN/db $RUN/queries --format=sarif-latest \
  --output=$RUN/custom.sarif <common options>
```

## Step 7: Findings → `$RUN/findings/`

Read `custom.sarif` (`runs[0].results[]`). A result can have several code flows: CodeQL groups different source-to-sink paths that end at the same sink into one result. Read **every** `codeFlows[i].threadFlows[0].locations[]` of every result, not only `codeFlows[0]`; each code flow is one candidate path. Drop consecutive duplicate path steps. Deduplicate by (rule, source location, sink location): keep one path per triple.

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
- Severity, using `threat_model.md` (e.g. which role can reach the source):
  - **High**: directly exploitable, leads to RCE, data breach, or authentication/privilege bypass.
  - **Medium**: needs specific conditions but has significant impact.
  - **Low**: defense-in-depth or low impact.

## Step 8: Verification → updates `$RUN/findings/`, writes `$RUN/final_vuls/`

Decide for each finding whether it is a real, exploitable vulnerability (**TP**) or a false positive (**FP**). This follows the false-positive filtering of Claude Code's `/security-review`.

### Materials

The verifier uses exactly these, all produced by the earlier steps:

| Material | From | Used for |
|---|---|---|
| `$RUN/findings/F<NNN>-<slug>.md` | Step 7 | the finding and its data flow (source → steps → sink) |
| `$RUN/recon.md` | Step 1 | permission model, persistent state, dynamic dispatch, existing security mechanisms |
| `$RUN/threat_model.md` | Step 2 | public interface, authentication, attackers, trusted inputs |
| `$RUN/spec.md` | Step 4 | why each source/sink/sanitizer/taint step was chosen |
| `<target-path>` source code | — | reading the code around every data-flow step |

Do not re-run CodeQL or re-read `custom.sarif`; the finding file already contains the path.

### Process

1. Launch one sub-agent per finding, in parallel, **at most 10 at a time**. Sub-agents only read code: no Bash, no file writes. Each sub-agent prompt contains the paths of the five materials above and the full rules below.
2. Each sub-agent returns: confidence (1–10), exploit scenario (if confidence ≥ 8), and a short justification that refers to the data-flow steps and rules below.
3. **Confidence ≥ 8 → TP; otherwise FP.**
4. The main agent writes all results back (see "Write back").

### Rules for the sub-agent

**A. Check the data flow step by step**

1. **Source**: is it attacker-controlled under `threat_model.md`? If it is listed as a trusted input, it is FP. For second-order sources, check which role can write the stored value.
2. **Reachability**: is the handler part of the public interface in `threat_model.md`? Which attacker can reach it, and with which permission?
3. **Each step**: does the code really pass the data along as shown? Check for dead code, values being overwritten, and type conversions such as `int()`.
4. **Sanitizers**: is there validation or escaping on the path that CodeQL did not model (including the mechanisms in `recon.md`)? Is it effective for this vulnerability type?
5. **Sink**: is it really dangerous with this data? E.g. a parameterized SQL query, an auto-escaped template, or `subprocess` with a list and no `shell=True` is not.

**B. Hard exclusions (always FP)**

- Code only in tests or only used for running tests.
- Denial of service, resource exhaustion, ReDoS.
- Log spoofing (unsanitized user input written to logs).
- Regex injection.
- SSRF that only controls the path, not the host or protocol.
- Missing hardening without a concrete vulnerability.

**C. Precedents**

- Environment variables and CLI flags are trusted values.
- UUIDs are unguessable and need no validation.
- `open_redirect` is TP only with extremely high confidence.
- A Medium-severity finding is TP only if it is obvious and concrete.

**D. Confidence**

- 1–3: likely false positive.
- 4–6: needs investigation.
- 7–10: likely a real vulnerability.

### Write back

For every finding file:

1. Add to the frontmatter: `status: TP` or `status: FP`, and `confidence: <1-10>`.
2. For TP, insert `* Exploit Scenario: ...` between `Description` and `Recommendation`, as in `/security-review`.
3. Append:
   ```markdown
   ## Verification

   * Verdict: TP | FP
   * Confidence: <1-10>
   * Reasoning: <justification, citing data-flow steps, threat model entries, or the exclusion/precedent applied>
   ```

Keep FP files; never delete them. `findings/` is the full record of everything CodeQL reported, with verdicts.

Then copy every TP finding file, unchanged and with the same file name, into `$RUN/final_vuls/`. `final_vuls/` holds only the final, confirmed vulnerabilities. If there are no TPs, create it empty.

## Step 9: Report → `$RUN/scan.md`

1. Target, run directory, vulnerability types scanned (with built-in module or "custom" for each).
2. Totals: number of findings, TP, FP.
3. Final vulnerabilities: table of the files in `final_vuls/`: ID, category, severity, confidence, sink, link to the file in `final_vuls/`.
4. All findings, TP first: ID, category, severity, status, confidence, sink, link to the file in `findings/`.
5. Count per type: findings / TP / FP.
6. Queries skipped because they failed to compile, with the last error.

Finally, give the user a short summary of the final vulnerabilities and the paths of `final_vuls/` and `scan.md`.
