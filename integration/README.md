# PakCyberbot environment integration

This folder holds the one change ReconX makes to the **PakCyberbot OSCP
environment** so its scripts can launch the recon engine automatically.
Everything else in ReconX is additive and lives outside PakCyberbot.

## What it changes

`setup_pentest_env` — an **additive** block appended after the IP-collection
step (nothing above it is modified). After you enter your target IPs it:

1. optionally prompts for initial credentials (username / password / NTLM hash
   / domain — press Enter to skip),
2. launches the two-pass orchestrator `recon-exam`
   (unauthenticated → learn domains → `/etc/hosts` → authenticated).

Credentials are written to a `chmod 600` temp file that `recon-exam` deletes
after reading, so they never persist in plaintext. Skipping the prompts leaves
`setup_pentest_env` behaving exactly as upstream.

## Files

- `setup_pentest_env` — the full patched script (drop-in replacement).
- `setup_pentest_env.patch` — the diff alone, appliable to a clean checkout.

## Apply it

Against an unmodified PakCyberbot checkout:

```bash
cd <PakCyberbot>/OSCP-Notes-and-Environment
git apply <this-repo>/integration/setup_pentest_env.patch
```

Or just install the patched copy + the two launchers system-wide:

```bash
sudo cp integration/setup_pentest_env /usr/local/bin/setup_pentest_env
sudo ln -sf "$PWD/recon"      /usr/local/bin/recon
sudo ln -sf "$PWD/recon-exam" /usr/local/bin/recon-exam
```
