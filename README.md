# dotenv-guard

Small tool that keeps secrets out of git.

Blocks committing `.env` / `.env.*` files and flags common secret patterns before they land in a repo. Built after leaking a key once. Once was enough.

## Install

```bash
pip install -e .
```

That puts `dotenv-guard` on your PATH. `python -m dotenv_guard` works too.

## Usage

Scan the current directory:

```bash
dotenv-guard
```

Same thing, spelled out:

```bash
dotenv-guard scan
```

Scan a few paths:

```bash
dotenv-guard scan app config
```

Check the git index (what the next commit will record):

```bash
dotenv-guard check-staged
```

A clean run prints `ok` and exits 0. If it finds something, it exits 1 and prints one line per hit:

```
.env.local: env file
app/settings.py:18: AWS access key
```

`.env.example` and `.env.sample` are allowed. `.env`, `.env.local`, `.env.production`, and any other `.env.*` are not. Case does not matter, so `.ENV` is blocked too.

`check-staged` only looks at staged files. A file you have not `git add`ed is ignored. Use `scan` to walk a directory.

It looks for:

- AWS access key ids (`AKIA...`) and `aws_secret_access_key` assignments
- Stripe live keys (`sk_live_...`, `rk_live_...`)
- PEM private keys
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- WooCommerce consumer keys and secrets (`ck_...`, `cs_...`)
- Slack tokens, Google API keys, npm tokens

This is a short list, not a full secret scanner.

Directory walks skip `.git`, `node_modules`, virtualenvs, and build folders. Only the first 1 MB of a file is scanned. A null byte in that chunk means the file is treated as binary.

## pre-commit

`.pre-commit-hooks.yaml` is in this repo. From another project:

```yaml
repos:
  - repo: https://github.com/kaygaaf/dotenv-guard
    rev: v0.1.0
    hooks:
      - id: dotenv-guard
```

Pin a rev that exists. The hook runs `dotenv-guard check-staged`.

To use the copy you installed locally:

```yaml
repos:
  - repo: local
    hooks:
      - id: dotenv-guard
        name: dotenv-guard
        entry: dotenv-guard check-staged
        language: system
        pass_filenames: false
        always_run: true
```

## Tests

```bash
python -m unittest
```

## Support

If this helps: [ko-fi.com/kayorama](https://ko-fi.com/kayorama)
