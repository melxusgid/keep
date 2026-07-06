"""Keep CLI — command-line interface for the encrypted secrets vault."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from keep.vault import Vault, Error, LockedError, CryptoError

# Global vault instance (lazy-loaded)
_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault()
    return _vault


def cmd_init(args):
    password = _prompt_password("Create master password: ", confirm=True)
    v = get_vault()
    v.init(password)
    print("Vault created at", v.path)
    return 0


def cmd_unlock(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    print("Vault unlocked.")
    if args.json:
        print('{"status":"unlocked"}')
    return 0


def cmd_lock(args):
    v = get_vault()
    v.lock()
    print("Vault locked.")
    return 0


def cmd_set(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    v.set(args.name, args.value, note=args.note or "")
    print(f"Secret '{args.name}' stored.")
    v.lock()
    return 0


def cmd_get(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    value = v.get(args.name)
    v.lock()
    if value is None:
        print(f"Secret '{args.name}' not found.", file=sys.stderr)
        return 1
    if args.json:
        import json
        print(json.dumps({"name": args.name, "value": value}))
    else:
        print(value)
    return 0


def cmd_list(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    secrets = v.list()
    v.lock()
    if args.json:
        import json
        print(json.dumps(secrets, indent=2))
    else:
        if not secrets:
            print("No secrets stored.")
            return 0
        for s in secrets:
            note = ""
            meta = s.get("metadata", {})
            if meta and meta.get("note"):
                note = f"  #{meta['note']}"
            print(f"  {s['name']}{note}")
    return 0


def cmd_delete(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    ok = v.delete(args.name)
    v.lock()
    if ok:
        print(f"Secret '{args.name}' deleted.")
    else:
        print(f"Secret '{args.name}' not found.", file=sys.stderr)
        return 1
    return 0


def cmd_rotate(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    new_val = v.rotate(args.name, length=args.length)
    v.lock()
    if args.json:
        import json
        print(json.dumps({"name": args.name, "value": new_val}))
    else:
        print(f"Secret '{args.name}' rotated: {new_val}")
    return 0


def cmd_audit(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    entries = v.audit(limit=args.limit)
    v.lock()
    if args.json:
        import json
        print(json.dumps(entries, indent=2))
    else:
        for e in entries:
            print(f"  {e['action']:8s} | {e['secret_name']:20s} | {e['context']:20s} | {e['timestamp']:.0f}")
    return 0


def cmd_env(args):
    password = _prompt_password("Master password: ")
    v = get_vault()
    v.unlock(password)
    secrets = v.env()
    v.lock()
    if args.json:
        import json
        print(json.dumps(secrets, indent=2))
    else:
        for name, value in secrets.items():
            key = name.upper()
            print(f"export {key}='{value}'")
    return 0


def cmd_status(args):
    v = get_vault()
    if not v.path.exists():
        print("No vault found. Run 'keep init' first.")
        return 0
    if v.locked:
        # Try to get basic info without unlocking
        print(f"Vault: {v.path}")
        print("Status: locked")
    else:
        try:
            s = v.stats()
            print(f"Vault: {s['path']}")
            print(f"Name: {s['vault_name']}")
            print(f"Secrets: {s['secret_count']}")
            print(f"Audit entries: {s['audit_entries']}")
            print(f"Status: unlocked")
        except LockedError:
            print(f"Vault: {v.path}")
            print("Status: locked")
    return 0


def cmd_serve(args):
    """Start the REST API server."""
    from keep.server import serve
    serve(host=args.host, port=args.port)


def _prompt_password(prompt: str, confirm: bool = False) -> str:
    """Read a password from the terminal with no echo."""
    try:
        import getpass
        pw = getpass.getpass(prompt)
        if confirm:
            pw2 = getpass.getpass("Confirm: ")
            if pw != pw2:
                print("Passwords don't match.", file=sys.stderr)
                sys.exit(1)
        if not pw:
            print("Password cannot be empty.", file=sys.stderr)
            sys.exit(1)
        return pw
    except KeyboardInterrupt:
        print()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="keep",
        description="Keep — encrypted secrets vault for agents and humans",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Create a new vault")
    sub.add_parser("unlock", help="Unlock the vault")
    sub.add_parser("lock", help="Lock the vault")

    p_set = sub.add_parser("set", help="Store a secret")
    p_set.add_argument("name", help="Secret name")
    p_set.add_argument("value", help="Secret value")
    p_set.add_argument("--note", "-n", help="Optional description")

    p_get = sub.add_parser("get", help="Retrieve a secret")
    p_get.add_argument("name", help="Secret name")

    sub.add_parser("list", help="List all secrets")
    sub.add_parser("env", help="Export secrets as environment variables")

    p_delete = sub.add_parser("delete", help="Delete a secret")
    p_delete.add_argument("name", help="Secret name")

    p_rotate = sub.add_parser("rotate", help="Generate and store a random secret")
    p_rotate.add_argument("name", help="Secret name")
    p_rotate.add_argument("--length", "-l", type=int, default=32, help="Length in chars")

    p_audit = sub.add_parser("audit", help="Show audit log")
    p_audit.add_argument("--limit", type=int, default=50)

    sub.add_parser("status", help="Show vault status")

    p_serve = sub.add_parser("serve", help="Start REST API server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=7391)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    cmd_map = {
        "init": cmd_init,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "set": cmd_set,
        "get": cmd_get,
        "list": cmd_list,
        "delete": cmd_delete,
        "rotate": cmd_rotate,
        "audit": cmd_audit,
        "env": cmd_env,
        "status": cmd_status,
        "serve": cmd_serve,
    }

    try:
        return cmd_map[args.command](args)
    except (Error, LockedError, CryptoError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 1


if __name__ == "__main__":
    sys.exit(main())
