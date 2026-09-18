"""The worker edge: stored values are read back and handed to the query helper."""
from jobstore import JobStore
from sqlite3 import Cursor
from search_queries import search, search_parameterized


def search_unvalidated_concat(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.unvalidated")
    search(term, cursor)


def search_validated_concat(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.validated")
    search(term, cursor)


def search_unvalidated_parameterized(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.unvalidated")
    search_parameterized(term, cursor)


def search_validated_parameterized(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.validated")
    search_parameterized(term, cursor)


def search_mutated_concat(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.mutated")
    search(term, cursor)


def search_other_value_concat(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.other_value")
    search(term, cursor)


def search_wrong_validator_concat(jobs: JobStore, cursor: Cursor):
    term = jobs.get("search.wrong_validator")
    search(term, cursor)
