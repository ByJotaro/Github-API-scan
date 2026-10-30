#!/usr/bin/env python3
"""ascan — unified CLI for Secret Scanner Pro.

Install (one command):
    pip install -e .          # exposes `ascan` anywhere via PATH

Usage:
    ascan                     # operator TUI (default)
    ascan --all-sources       # headless scan (same flags as main_optimized.py)
    ascan --stats             # DB stats
    ascan upgrade             # pull latest code (private repo), keep config_local.py + *.db
"""
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(BASE_DIR, "main_optimized.py")


def _run_git(*args: str) -> tuple:
    try:
        p = subprocess.run(
            ["git", *args], cwd=BASE_DIR,
            capture_output=True, text=True, timeout=60,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as exc:
        return 1, "", str(exc)


def cmd_upgrade() -> int:
    """git pull --ff-only; NEVER touch config_local.py / *.db (gitignored)."""
    print("ascan upgrade: checking private repo for updates...")
    code, _, err = _run_git("rev-parse", "--is-inside-work-tree")
    if code != 0:
        print("[ERROR] not a git checkout — clone the private repo first.")
        return 1
    _run_git("fetch", "origin")
    code, local, _ = _run_git("rev-parse", "HEAD")
    code2, remote, _ = _run_git("rev-parse", "@{u}")
    if code != 0 or code2 != 0:
        print("[ERROR] cannot resolve revisions:", err)
        return 1
    if local == remote:
        print("[OK] already up to date.")
        return 0
    # Safety: refuse if user has local edits to tracked files (avoid clobber).
    code, status, _ = _run_git("status", "--porcelain")
    if code == 0 and status:
        print("[WARN] local modifications present — stashing them first:")
        print(status[:2000])
        c, _, e = _run_git("stash", "push", "-m", "ascan-upgrade-autostash")
        if c != 0:
            print("[ERROR] stash failed:", e)
            return 1
    print("Pulling (fast-forward only)...")
    code, out, err = _run_git("pull", "--ff-only")
    print(out or err)
    if code != 0:
        print("[ERROR] pull failed (diverged?). Resolve manually: git status")
        return 1
    print("[OK] upgraded. config_local.py + *.db untouched (gitignored).")
    print("Restart TUI to use the new code.")
    return 0


def cmd_version() -> int:
    code, tag, _ = _run_git("describe", "--tags", "--always", "--dirty")
    code2, subj, _ = _run_git("log", "-1", "--format=%h %s")
    print(f"ascan @ {BASE_DIR}")
    if code == 0:
        print(f"rev: {tag}")
    if code2 == 0:
        print(f"tip: {subj}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "upgrade":
        return cmd_upgrade()
    if argv and argv[0] in ("version", "--version", "-V"):
        return cmd_version()
    # Everything else → unified entry (bare run opens TUI by default).
    os.execv(sys.executable, [sys.executable, MAIN, *argv])


if __name__ == "__main__":
    raise SystemExit(main())
