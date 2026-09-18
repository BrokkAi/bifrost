"""The application job store the scenario's policies are configured for.

The store is deliberately opaque to the analyzer: `put` and `get` have empty
bodies, so a value can cross from a write to a read only through the declared
store endpoint set, never through observed behavior.
"""
from typing import final


@final
class JobStore:
    def put(self, key, value):
        pass

    def get(self, key):
        return ""
