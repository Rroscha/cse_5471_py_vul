# cse_5471_py_vul

LLM-agent-assisted static vulnerability detection for Python web projects.

Static analysis tools such as CodeQL find vulnerabilities by tracking untrusted data from sources to sinks, but only for the sources and sinks they already model. When a project uses its own wrappers, third-party libraries, dynamic dispatch, or stores attacker data and reads it back later, taint paths break and real vulnerabilities are missed, while generic rules also produce false positives.

This project uses an LLM agent (Claude Code) to fill that gap:

1. **Source and sink identification**: the agent reads the project and identifies untrusted inputs, dangerous operations, and sanitizers.
2. **Rule generation**: the agent turns these into project-specific CodeQL queries, and CodeQL runs the scan.
3. **Verification**: the agent reviews each finding with its code context and labels it a true or false positive.

The whole pipeline is packaged as Claude Code skills.

## Repository layout

```
cse_5471_py_vul/
├── .claude/skills/
│   ├── codeql/SKILL.md      # install / locate the project-local CodeQL CLI
│   └── vul-scan/SKILL.md    # the scanning pipeline
├── tools/codeql/            # CodeQL bundle (installed locally, not committed)
├── repos/                   # target projects to scan
└── runs/                    # scan outputs, one directory per run
```

## Setup

1. Create and activate the Python environment:
   ```bash
   conda create -n pyvul python=3.12 -y
   conda activate pyvul
   ```
2. Install CodeQL into `tools/codeql/` (latest bundle, includes the Python query packs). In Claude Code, run the `codeql` skill, or manually:
   ```bash
   mkdir -p tools
   curl -L -o tools/codeql-bundle.tar.gz \
     https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
   tar -xzf tools/codeql-bundle.tar.gz -C tools/ && rm tools/codeql-bundle.tar.gz
   tools/codeql/codeql version
   ```
   CodeQL is not added to the global `PATH`; the skills prefix it on each command.
3. Put the target project under `repos/`, e.g.:
   ```bash
   git clone https://github.com/pyload/pyload.git repos/pyload
   ```

## Usage

In Claude Code, from the repository root:

```
/vul-scan <target-path> [--types <slug,...>] [--out <name>]
```

| Argument | Meaning | Default |
|---|---|---|
| `<target-path>` | Python web project to scan | required |
| `--types` | Restrict to these vulnerability types, e.g. `sql_injection,path_traversal` | every applicable type |
| `--out` | Name of the output directory | basename of the target |

Example:

```
/vul-scan repos/pyload
```

## Pipeline

| Step | What the agent does | Output |
|---|---|---|
| 0. Setup | Check CodeQL, create the run directory | `runs/<name>-<timestamp>/` |
| 1. Recon | Map the whole repository: entry points, plugins/extensions, roles and permissions, attacker-writable persistent state, dynamic dispatch, existing security mechanisms | `recon.md` |
| 2. Threat model | Public interface, attackers and what they can reach, trusted inputs | `threat_model.md` |
| 3. Database | Build the CodeQL database (tests, venvs, migrations excluded) | `db/` |
| 4. Spec | Choose every applicable vulnerability type; identify project-specific sources (direct, dynamic-dispatch, second-order), sinks, sanitizers, taint steps | `spec.md` |
| 5. Queries | One taint-tracking query per type, extending CodeQL's built-in model when one exists, custom otherwise | `queries/` |
| 6. Scan | Run the queries | `custom.sarif` |
| 7. Findings | One Markdown file per result, with the full data flow | `findings/` |
| 8. Verification | One read-only sub-agent per finding, using the false-positive rules of Claude Code's `/security-review`; confidence ≥ 8 is TP | updates `findings/`, writes `final_vuls/` |
| 9. Report | Summary of all findings and final vulnerabilities | `scan.md` |

## Output

```
runs/<name>-<timestamp>/
├── recon.md
├── threat_model.md
├── codeql-config.yml
├── db/
├── spec.md
├── queries/
│   ├── qlpack.yml
│   ├── ProjectModels.qll
│   └── <slug>.ql
├── custom.sarif
├── findings/          # every CodeQL result, labeled TP or FP
│   └── F001-<slug>.md
├── final_vuls/        # confirmed vulnerabilities only (TP)
│   └── F00N-<slug>.md
└── scan.md
```

Each finding file looks like:

````markdown
---
id: F001
category: sql_injection
severity: high
rule: pyvul/sql-injection
source: app/views.py:42
sink: app/db.py:88
status: TP
confidence: 9
---

# F001: SQL Injection: `app/db.py:88`

* Severity: High
* Description: ...
* Exploit Scenario: ...
* Recommendation: ...

## Data flow

1. **Source** `app/views.py:42` ...
2. **Sink** `app/db.py:88` ...

## Verification

* Verdict: TP
* Confidence: 9
* Reasoning: ...
````
