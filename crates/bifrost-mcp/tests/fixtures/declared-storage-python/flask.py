"""Fixture declaration of the Flask request surface used by the scenario.

`RequestValues` declares the query-values mapping a Flask handler reads as
`request.args`: the one member the scenario uses is `get(key)`, spelled the
way Flask's MultiDict spells it. A handler receives the current request's
query values as an annotated collaborator so each endpoint call names one
exact declaration.
"""
from typing import final


@final
class RequestValues:
    """Stand-in for the `request.args` MultiDict."""

    def get(self, key):
        return ""
