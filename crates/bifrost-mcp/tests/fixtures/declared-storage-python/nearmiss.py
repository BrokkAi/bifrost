"""Unrelated APIs that share member names with the scenario's endpoints.

Every class here shares a member name with a configured endpoint (`put`,
`get`, `execute`, `validate`) and is otherwise unrelated. Exact selection
must keep every call to these classes out of every finding and obligation.
"""
from typing import final


@final
class JobCache:
    """An unrelated class with `put`/`get` members like the job store's."""

    def put(self, key, value):
        pass

    def get(self, key):
        return ""


@final
class DbCursor:
    """An unrelated class with an `execute` member like the DB cursor's."""

    def execute(self, sql, parameters=()):
        return self


@final
class OtherValidator:
    """An unrelated class with a `validate` member; never the configured kill."""

    @staticmethod
    def validate(value):
        return value
