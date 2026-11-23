"""Append-only scan history in SQLite, and portable exports."""

import json
import sqlite3
from pathlib import Path


def save_database(path, results, metadata):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, metadata_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
                domain TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL,
                UNIQUE(run_id, domain));
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL REFERENCES domains(id),
                query_name TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL,
                resolver TEXT NOT NULL, fetched_at TEXT NOT NULL, source_url TEXT,
                via_json TEXT NOT NULL, error TEXT);
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY, query_id INTEGER NOT NULL REFERENCES queries(id),
                record_index INTEGER NOT NULL, owner TEXT NOT NULL, value TEXT NOT NULL,
                raw TEXT, ttl INTEGER, UNIQUE(query_id, record_index));
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL REFERENCES domains(id),
                record_id INTEGER NOT NULL REFERENCES records(id), rule_id TEXT NOT NULL,
                service TEXT NOT NULL, category TEXT NOT NULL, signal TEXT NOT NULL,
                confidence TEXT NOT NULL, matched TEXT NOT NULL, sources_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS matches_service ON matches(service);
            CREATE INDEX IF NOT EXISTS domains_name ON domains(domain);
        """)
        run_id = db.execute("INSERT INTO runs(created_at, metadata_json) VALUES (?,?)",
                            (metadata["created_at"], json.dumps(metadata))).lastrowid
        for result in results:
            domain_id = db.execute(
                "INSERT INTO domains(run_id,domain,status,result_json) VALUES (?,?,?,?)",
                (run_id, result["domain"], result["status"], json.dumps(result))).lastrowid
            record_ids = {}
            for query in result["queries"]:
                query_id = db.execute(
                    "INSERT INTO queries(domain_id,query_name,scope,status,resolver,fetched_at,source_url,via_json,error) VALUES (?,?,?,?,?,?,?,?,?)",
                    (domain_id, query["query_name"], query.get("scope", "apex"), query["status"],
                     query["resolver"], query["fetched_at"], query.get("source_url"),
                     json.dumps(query.get("via", [])), query.get("error"))).lastrowid
                for index, record in enumerate(query["records"]):
                    record_id = db.execute(
                        "INSERT INTO records(query_id,record_index,owner,value,raw,ttl) VALUES (?,?,?,?,?,?)",
                        (query_id, index, record["owner"], record["value"], record.get("raw"), record.get("ttl"))).lastrowid
                    record_ids[(query["query_name"], index)] = record_id
            for match in result["matches"]:
                db.execute(
                    "INSERT INTO matches(domain_id,record_id,rule_id,service,category,signal,confidence,matched,sources_json) VALUES (?,?,?,?,?,?,?,?,?)",
                    (domain_id, record_ids[(match["query_name"], match["record_index"])],
                     match["rule_id"], match["service"], match["category"], match["signal"],
                     match["confidence"], match["matched"], json.dumps(match["sources"])))
    return run_id


def summary(results):
    return {
        "domains": len(results),
        "domains_with_txt": sum(any(q["records"] for q in r["queries"]) for r in results),
        "domains_with_matches": sum(bool(r["services"]) for r in results),
        "domains_with_errors": sum(r["status"] in ("error", "partial") for r in results),
        "txt_records": sum(len(q["records"]) for r in results for q in r["queries"]),
        "company_service_pairs": sum(len(r["services"]) for r in results),
        "distinct_services": len({s["service"] for r in results for s in r["services"]}),
        "evidence_matches": sum(len(r["matches"]) for r in results),
    }
