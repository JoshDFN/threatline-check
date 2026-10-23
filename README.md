# Threatline check

Fails a pull request when it ships a dependency that attackers are using: a malicious release, a vulnerability that is known to be exploited, or (if you choose) any critical issue. Everything else is reported without blocking, so the check stays green for the things that can wait.

It reads lockfiles, SBOMs, Dockerfiles and compose files, downloads only the Threatline package indexes it needs, and matches versions on the runner. Your dependency list never leaves the runner.

## Use it

```yaml
# .github/workflows/threatline.yml
name: Threatline
on:
  pull_request:
  schedule:
    - cron: '17 6 * * *'   # daily: catches dependencies that became exploited since the last change
permissions:
  contents: read
  pull-requests: write     # for the pull request comment
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JoshDFN/threatline-check@v1
```

On a pull request it posts one comment (updated on every run) and annotates the lockfile lines. Every run writes a job summary.

## What fails

| `fail-on` | Fails on |
|---|---|
| `malicious` | Releases attackers took over (for example litellm 1.107.0) |
| `exploited` (default) | The above, plus vulnerabilities in CISA's known exploited catalog, rated actively exploited by CISA, or reported exploited by at least two independent outlets |
| `critical` | The above, plus critical severity |
| `high` | The above, plus high severity |
| `any` | Any known vulnerability |
| `none` | Nothing; report only |

Issues with no fixed version yet are reported but do not fail unless `fail-without-fix: true`, since there is nothing to upgrade to. Malicious releases always fail: the fix is to remove them and rotate credentials, not to upgrade.

## Inputs

| Input | Default | |
|---|---|---|
| `path` | `.` | Directory to scan, recursively. `node_modules`, `vendor`, `.git` and build folders are skipped. |
| `fail-on` | `exploited` | See above. |
| `fail-without-fix` | `false` | Also fail when no fixed version exists. |
| `ignore` | | IDs to accept, comma or newline separated. |
| `ignore-file` | `.threatline-ignore` | One ID per line: `CVE-2026-1234 until 2026-12-31 # reason`. Lines stop applying after their date. |
| `comment` | `true` | Pull request comment. Needs `pull-requests: write`. |
| `sarif-file` | | Write SARIF for `github/codeql-action/upload-sarif`, so findings appear in the Security tab. |
| `report-file` | | Write the Markdown report to a file. |
| `on-api-error` | `warn` | If Threatline cannot be reached: `warn` and pass, or `fail`. |

Outputs: `failed`, `findings`, `exploited`, `malicious`, `report`.

## What it reads

`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Gemfile.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, CycloneDX and SPDX JSON, and `Dockerfile` / compose files for official images (php, node, python, nginx, postgres, redis, gitlab and others). Image tags must name a full version, such as `php:8.3.36`; floating tags like `php:8.3` are listed as not checked.

## GitLab CI and other CI systems

The check is one Node file with no dependencies, so it runs anywhere Node 18 or later does. The exit code fails the pipeline.

```yaml
# .gitlab-ci.yml
threatline:
  image: node:22
  script:
    - git clone --depth 1 --branch v1 https://github.com/JoshDFN/threatline-check /tmp/threatline
    - node /tmp/threatline/index.mjs . --fail-on exploited --report-file threatline.md
  artifacts:
    when: always
    paths: [threatline.md]
```

Add a scheduled pipeline to catch dependencies that become exploited after they were merged.

## From a shell

```sh
node index.mjs path/to/repo --fail-on exploited
node index.mjs . --json > threatline.json
```

The matching rules are the same file the website's stack check uses (`stackcore.js`), so results agree with threatline.ai.
