"""The application validators the scenario's policies can be configured for."""
from typing import final


@final
class SearchTermValidator:
    """The validator the reviewed configuration requires before storage."""

    @staticmethod
    def validate(value):
        return value
