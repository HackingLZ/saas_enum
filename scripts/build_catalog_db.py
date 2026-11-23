"""Build a local SQLite rules database from the distributable JSON catalog."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.txt_matcher import DEFAULT_RULES, load_rules


def build_database(catalog_path, output_path):
    catalog_path, output_path = Path(catalog_path), Path(output_path)
    catalog = load_rules(catalog_path)
    digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Reserve a new file; never replace an existing rules or scan database.
    with output_path.open("xb"):
        pass
    try:
        with closing(sqlite3.connect(output_path)) as db, db:
            db.executescript("""
                CREATE TABLE catalog_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE fingerprints (
                    rule_id TEXT PRIMARY KEY, service TEXT NOT NULL, category TEXT NOT NULL,
                    kind TEXT NOT NULL, pattern TEXT, domains_json TEXT, confidence TEXT NOT NULL,
                    basis TEXT NOT NULL, sources_json TEXT NOT NULL, rule_json TEXT NOT NULL);
                CREATE INDEX fingerprints_service ON fingerprints(service);
            """)
            db.executemany("INSERT INTO catalog_metadata VALUES (?, ?)",
                           [("version", catalog["version"]), ("file_sha256", digest)])
            db.executemany("INSERT INTO fingerprints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                (r["id"], r["service"], r["category"], r["kind"], r.get("pattern"),
                 json.dumps(r.get("domains")), r["confidence"], r["basis"],
                 json.dumps(r["sources"]), json.dumps(r)) for r in catalog["rules"]
            ])
        return len(catalog["rules"])
    except Exception:
        output_path.unlink()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprints", type=Path, default=DEFAULT_RULES,
                        help="JSON rules catalog (defaults to the bundled catalog)")
    parser.add_argument("--output", type=Path, default=Path("data/technology_map.sqlite"),
                        help="New SQLite file; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        count = build_database(args.fingerprints, args.output)
    except FileExistsError:
        parser.exit(2, f"error: {args.output} already exists; choose a new --output path\n")
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(f"Created {args.output} with {count} fingerprints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
