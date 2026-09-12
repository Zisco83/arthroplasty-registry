"""Optional legacy migration helper.
The supplied CLI prototype uses normalized SQLite tables. This script copies the
raw legacy tables into PostgreSQL staging tables so data can be reconciled before
being mapped into the web JSON model. It deliberately does not silently transform
clinical data.
"""
import os, sqlite3, json
from sqlalchemy import create_engine, text

SQLITE_PATH=os.environ.get('LEGACY_SQLITE','arthroplasty.db')
DATABASE_URL=os.environ['DATABASE_URL']
conn=sqlite3.connect(SQLITE_PATH); conn.row_factory=sqlite3.Row
pg=create_engine(DATABASE_URL)

tables=['users','patients','procedures','preop','intraop','implants','followup','audit_log']
with pg.begin() as c:
    c.execute(text('CREATE TABLE IF NOT EXISTS legacy_import (table_name TEXT NOT NULL, row_json JSONB NOT NULL, imported_at TIMESTAMPTZ DEFAULT NOW())'))
    for table in tables:
        for row in conn.execute(f'SELECT * FROM {table}'):
            c.execute(text('INSERT INTO legacy_import(table_name,row_json) VALUES (:t,CAST(:j AS jsonb))'), {'t':table,'j':json.dumps(dict(row), default=str)})
print('Imported legacy rows into PostgreSQL legacy_import. Review and map before production use.')
