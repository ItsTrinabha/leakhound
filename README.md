# leakhound

**Find leaked secrets in source code and git history before attackers do.**

leakhound is a fast, dependency-free secrets scanner for codebases and CI pipelines. It finds API keys, access tokens, private keys, database passwords and other credentials using two complementary techniques. The first is a curated set of **29 provider-specific rules** (AWS, GitHub, Stripe, Slack, Google, OpenAI and more). The second is **Shannon-entropy analysis** that catches random-looking secrets with no known format. Layered false-positive filters keep the output something people will actually read.

```
$ leakhound git ./my-repo
leakhound 1.0.0  scanned 5 commits (6 file changes) in 0.01s

[CRITICAL] Stripe Live Secret Key (stripe-live-key)
    location : app.py:3:15
    secret   : sk_l********   entropy 4.54
    code     : STRIPE_KEY = 'sk_l********'
    commit   : 794d748db0b9  Demo Dev <dev@demo.invalid>  2026-10-11T12:31:09+00:00
    message  : Add payments (quick hack)

[CRITICAL] Private Key (private-key)
    location : deploy/id_rsa:1:1
    secret   : -----BEGIN RSA PRIVATE KEY----- ********   entropy 6.02
    commit   : 611b43db160c  Demo Dev <dev@demo.invalid>  2026-10-11T12:31:09+00:00
    message  : Deploy config

Found 4 potential secret(s): 2 critical, 1 high, 1 medium
Rotate any real credential above before removing it; deleting it from code does not revoke it.
```

Both of those secrets were "deleted" in later commits. `leakhound scan` on the current files reports nothing; `leakhound git` finds them in history, along with the commit and author that introduced them.

---

## Features

| | |
|---|---|
| **Two detection engines** | 29 named regex rules with validators, plus length-aware Shannon-entropy detection for generic secrets |
| **Three scan modes** | current files (`scan`), full git history (`git`), or staged changes for pre-commit hooks (`git --staged`) |
| **Low noise** | placeholder and stop-word filtering, JWT and PEM structure validation, identifier/path/hash/blob heuristics, test-path downgrading, `.gitignore` support, binary and lock-file skipping |
| **CI-ready** | console, JSON and **SARIF 2.1.0** output (GitHub code scanning), deterministic exit codes, `--fail-on` severity gates |
| **Adoptable on legacy code** | baseline files suppress accepted findings by a fingerprint that survives line moves |
| **Safe by default** | secrets are masked in every output format unless you pass `--no-redact` |
| **Zero dependencies** | pure Python standard library (3.11+); runs anywhere git and Python do |
| **Extensible** | add custom rules, allowlists and thresholds in `.leakhound.toml` |

## Installation

```bash
pip install .            # from a checkout
# or, for development
pip install -e ".[dev]"
```

This installs the `leakhound` command. You can also run it without installing via `python -m leakhound`.

## Quick start

```bash
leakhound scan .                       # scan the current files of a project
leakhound git .                        # scan every line ever committed, on all branches
leakhound git . --staged               # scan only what is about to be committed
leakhound git . --log-opts "origin/main..HEAD"   # scan only new commits in a PR
leakhound rules                        # list all detection rules
```

Exit codes are stable and meant for automation:

| Code | Meaning |
|------|---------|
| `0` | no findings at or above `--fail-on` (default `low`) |
| `1` | secrets found |
| `2` | usage, configuration or runtime error (bad path, not a git repo, invalid config) |

## Usage

```
leakhound {scan,git,rules} [PATH] [options]

output:
  -f, --format {console,json,sarif}   report format (default: console)
  -o, --output FILE                   write the report to a file
  --no-redact                         print secrets in full (default: masked)
  --no-color                          disable ANSI colours (also honours NO_COLOR)
  --min-severity SEV                  only report findings at or above SEV

CI gating:
  --fail-on SEV                       exit 1 if any finding is >= SEV (default: low)
  --exit-zero                         always exit 0 unless an error occurs

detection:
  -c, --config FILE                   config file (default: <path>/.leakhound.toml)
  --baseline FILE                     JSON report of accepted findings to suppress
  --disable-rule ID                   disable a rule (repeatable)
  --no-entropy                        disable generic high-entropy detection
  --exclude-tests                     drop findings in test/fixture paths
  --max-file-size BYTES               skip larger files (default 1 MiB)

scan only:   --no-gitignore           also scan files ignored by .gitignore
git only:    --staged | --log-opts OPTS
```

Severities are `low`, `medium`, `high` and `critical`.

## What it detects

| Rule ID | Severity | Detects |
|---|---|---|
| `private-key` | critical | RSA / EC / DSA / OpenSSH / PGP / PKCS#8 private key blocks (also JSON-escaped, e.g. GCP service accounts) |
| `aws-access-key-id` | high | AWS access key IDs (`AKIA…`, `ASIA…`) |
| `aws-secret-access-key` | critical | AWS secret keys assigned to AWS-named variables |
| `github-token` | critical | GitHub `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` tokens |
| `github-fine-grained-pat` | critical | GitHub fine-grained PATs (`github_pat_…`) |
| `gitlab-pat` | critical | GitLab personal access tokens |
| `google-api-key` | high | Google / Firebase API keys |
| `google-oauth-client-secret` | high | Google OAuth client secrets |
| `slack-token` | high | Slack bot / user / app tokens |
| `slack-webhook-url` | medium | Slack incoming webhooks |
| `stripe-live-key` | critical | Stripe live secret and restricted keys |
| `stripe-test-key` | low | Stripe test keys |
| `twilio-api-key` | high | Twilio API key SIDs |
| `sendgrid-api-key` | high | SendGrid API keys |
| `npm-token` | high | npm publish tokens |
| `pypi-token` | high | PyPI upload tokens |
| `openai-api-key` | high | OpenAI API keys |
| `anthropic-api-key` | high | Anthropic API keys |
| `huggingface-token` | high | Hugging Face tokens |
| `shopify-token` | high | Shopify access tokens |
| `digitalocean-token` | high | DigitalOcean tokens |
| `hashicorp-vault-token` | critical | Vault service / batch / recovery tokens |
| `azure-storage-account-key` | critical | Azure Storage account keys in connection strings |
| `databricks-token` | high | Databricks PATs |
| `telegram-bot-token` | medium | Telegram bot tokens |
| `discord-webhook-url` | medium | Discord webhooks |
| `jwt` | medium | JSON Web Tokens (header must decode to JSON with `alg`) |
| `credentials-in-url` | high | `scheme://user:password@host` URLs and DSNs |
| `generic-secret` | medium | literals assigned to `password`, `secret`, `token`, `api_key`… (code, `.env`, YAML, JSON) |
| `high-entropy-string` | medium | random base64-like values in assignments (entropy engine) |
| `high-entropy-hex` | low | random hex values in assignments (entropy engine) |

## How detection works

```
file / diff hunk ──► keyword pre-filter ──► regex rules ──► validators ──► allowlist ──┐
                                                                                        ├──► findings ──► test-path policy ──► baseline ──► report
                     entropy candidates ──► shape filters ──► entropy threshold ───────┘
```

**Regex rules.** Each rule lists lower-case keywords, and a rule only runs on text that contains one of them, so adding rules costs little. A match then passes through:

* *Minimum entropy.* Discards low-randomness matches.
* *Validators.* A JWT must decode to a JSON header with `alg`. A PEM block must contain a real base64 body, not `...`. A generic password must not be a URL, file name, `${VAR}`, code expression such as `token[0]` or `self.x`, constant name or plain word.
* *Overlap resolution.* Specific rules run first, so a GitHub token assigned to `TOKEN = "..."` is reported once as `github-token`, not again as `generic-secret`.

**Entropy engine.** It looks at base64/hex runs of at least 20 characters that sit in a *value position* (quoted, or after `=` / `:`, but not `==`, `!=` or `-=`). It skips a run when any of these hold:

* It is a UUID, or part of a data URI or a multi-line base64 blob (embedded images, fonts).
* It sits next to words like `sha256`, `integrity`, `commit` or `git`.
* It lacks mixed character classes.
* It splits into dictionary-like pieces. `sizeEndCentDir64Locator` averages 3.8 characters per camelCase piece, while random strings average under 2.

Survivors are compared against a **length-aware threshold**. Short strings cannot reach high entropy (a 20-character string tops out at log2(20) ≈ 4.32 bits), so the configured threshold (default 4.5) applies in full at 40+ characters and scales down by log2(n)/log2(40) below that. In testing this detects about 95% of random 20-character tokens and 100% of 64-character tokens.

**Results on real code.** Running the default configuration over 5,781 files (73 MB) of popular third-party Python packages produced zero critical findings and 3 high ones (all example credentials in URL docstrings). There were 56 findings in total, mostly low-severity hex test vectors. The CPython standard library (602 files, 11 MB) produces 3 findings, all literal random-token examples in docstrings.

**Git history.** `leakhound git` streams `git log -p -U0 --all` and scans only *added* lines, grouped per hunk so multi-line keys stay intact and line numbers map to the file at that commit. A secret that appears in many commits is reported once, attributed to the **oldest commit that introduced it**.

## Reducing noise

From most to least targeted:

1. **Inline:** append `leakhound:allow` to a line (in any comment syntax).
2. **Baseline:** accept the current state of a legacy repo, then fail only on *new* leaks:
   ```bash
   leakhound scan . -f json -o .leakhound-baseline.json   # record today's findings
   leakhound scan . --baseline .leakhound-baseline.json   # later runs: only new ones
   ```
   Fingerprints hash the rule, path and secret, not the line number, so moving code around does not resurrect accepted findings.
3. **Config file:** `.leakhound.toml` at the scan root (or `--config`):
   ```toml
   [scan]
   max_file_size = 1048576
   exclude_tests = false          # true: drop test/fixture findings entirely
   disabled_rules = ["stripe-test-key"]

   [entropy]
   base64_threshold = 4.5
   hex_threshold = 3.0
   min_length = 20

   [allowlist]
   paths = ["docs/*", "*.snap"]   # globs; no "/" = match any path component
   regexes = ["^AKIA.*TEST$"]     # secrets matching these are ignored
   stopwords = ["not-a-real"]     # secrets containing these are ignored

   [[rules]]                      # your own token formats
   id = "acme-api-key"
   name = "ACME API Key"
   regex = "acme_[a-z0-9]{32}"
   severity = "critical"
   keywords = ["acme_"]
   ```
   Unknown keys, bad types and invalid regexes are rejected with a clear error and exit code 2, so a typo never silently disables scanning.

Built-in behaviour you get for free:

* Dependency and cache directories (`node_modules`, `vendor`, `.venv`…), lock files, minified bundles, source maps and binary formats are skipped. Files containing NUL bytes are treated as binary.
* In a git work tree, `scan` honours `.gitignore` (turn this off with `--no-gitignore`).
* Placeholders such as `your_token_here`, `xxxxxxxx`, `${VAR}`, `{{ var }}`, `<your-key>`, `changeme` and AWS's documented `…EXAMPLE` keys are ignored.
* Findings in test paths (`tests/`, `__tests__/`, `fixtures/`, `*_test.go`, `*.spec.ts`…) are tagged `test-path` and reported one severity lower. Use `--exclude-tests` to drop them.

## CI integration

**GitHub Actions + code scanning (SARIF):**

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # full history for `leakhound git`
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install git+https://github.com/<owner>/leakhound@v1.0.0
      - run: leakhound git . --format sarif --output leakhound.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: leakhound.sarif
```

Findings then appear as code-scanning alerts on the exact line. `partialFingerprints` keep alerts stable across runs, and `security-severity` drives GitHub's severity badges. Secrets are masked in SARIF messages and snippets.

**pre-commit:** this repository ships a `.pre-commit-hooks.yaml`:

```yaml
repos:
  - repo: <url of this repository>
    rev: v1.0.0
    hooks:
      - id: leakhound
```

**Any CI:** `leakhound scan . --fail-on high` fails the build only on high and critical findings. Use `-f json` for machine processing.

## Python API

```python
from pathlib import Path
from leakhound import Settings, scan_path, scan_git

result = scan_path(Path("."), Settings())
for f in result.findings:
    print(f.severity.label, f.rule_id, f"{f.path}:{f.line}", f.display_secret())

history = scan_git(Path("."), Settings(), log_opts=["--since=30.days"])
```

## Project layout

```
leakhound/
  models.py      Finding, Severity, CommitInfo, redaction, fingerprints
  rules.py       built-in rules, validators
  entropy.py     Shannon entropy, candidate extraction, shape filters
  config.py      Settings, Allowlist, .leakhound.toml loading, baselines
  detector.py    runs rules + entropy over a chunk of text
  scanner.py     directory walking, git log/diff parsing, de-duplication
  reporters/     console, json, sarif
  cli.py         argument parsing and exit codes
tests/           124 tests; fixtures/ holds leaky and clean sample projects
scripts/         make_demo_repo.py builds a repo with secrets buried in history
```

## Development

```bash
pip install -e ".[dev]"
pytest                                   # 124 tests, ~1.5 s
python scripts/make_demo_repo.py /tmp/demo && leakhound git /tmp/demo
```

**About the test fixtures.** `tests/fixtures/leaky_project` contains 25 planted secrets across `.py`, `.js`, `.env`, YAML and a bare key file. They are written as `{{PLACEHOLDERS}}` that `tests/fakes.py` fills with deterministic, randomly generated fakes at test time. No credential-shaped string is ever committed, so the repository passes its own scan, which is itself a test, and never trips push protection. The end-to-end test asserts that every planted secret is found exactly once, with the right rule, file and line. `tests/fixtures/clean_project` is full of near-misses (env lookups, placeholders, UUIDs, commit SHAs, lock-file hashes, data URIs, binaries) and must produce zero findings. A set of pathological inputs guards every rule against catastrophic regex backtracking (ReDoS).

## Limitations

* Detection is static. leakhound does not call provider APIs to check whether a key is live, which keeps it offline and side-effect free. Treat every finding as live until you have rotated it.
* Secrets that are split, encoded or encrypted in source will not be found.
* Entropy detection is a heuristic. Tune it with `[entropy]` thresholds or disable it with `--no-entropy`.

## If you find a real secret

1. **Revoke or rotate it first.** Removing it from the code does not invalidate it, and it remains in git history and in every clone.
2. Check the provider's access logs for use since the commit date shown in the finding.
3. Then remove it from the code and, if needed, from history (`git filter-repo`), and add it to `.gitignore` or a secrets manager.

## License

MIT
