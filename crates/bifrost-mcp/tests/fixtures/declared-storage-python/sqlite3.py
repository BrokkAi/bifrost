"""Fixture declaration of the sqlite3 cursor surface used by the scenario.

The signature matches the DB-API contract the scenario exercises:
`execute(sql, parameters)` runs one SQL statement; passing the value in
`parameters` binds it through the driver's own placeholder contract instead
of adding it to the SQL text.
"""
from typing import final


@final
class Cursor:
    def execute(self, sql, parameters=()):
        return self
