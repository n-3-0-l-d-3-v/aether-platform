"""Version constants.

SCHEMA_VERSION is the on-disk SQLite schema version. It is bumped only by a
migration in ultron/project/migrations.py. ULTRON_VERSION is the software
version and is recorded in run provenance so results stay attributable.
"""

ULTRON_VERSION = "0.1.0"

# On-disk schema version. Must equal the highest migration id.
SCHEMA_VERSION = 1

# Version of the deterministic export format (graph/*.jsonl).
EXPORT_FORMAT_VERSION = 1
