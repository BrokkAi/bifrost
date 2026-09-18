"""The web edge: request values enter the declared job store.

One handler per scenario channel. The store key names the channel, so the
four validator-present/absent x concatenated/parameterized combinations and
every control stay separate in one run.
"""
from flask import RequestValues
from jobstore import JobStore
from validators import SearchTermValidator
from nearmiss import JobCache, OtherValidator


def store_unvalidated(args: RequestValues, jobs: JobStore):
    term = args.get("q")
    jobs.put("search.unvalidated", term)


def store_validated(args: RequestValues, jobs: JobStore):
    term = SearchTermValidator.validate(args.get("q"))
    jobs.put("search.validated", term)


def store_mutated(args: RequestValues, jobs: JobStore):
    term = SearchTermValidator.validate(args.get("q"))
    term = term + "!"
    jobs.put("search.mutated", term)


def store_validated_other_value(args: RequestValues, jobs: JobStore):
    term = args.get("q")
    checked = SearchTermValidator.validate("constant")
    jobs.put("search.other_value", term)


def store_wrong_validator(args: RequestValues, jobs: JobStore):
    term = OtherValidator.validate(args.get("q"))
    jobs.put("search.wrong_validator", term)


def store_near_miss(args: RequestValues, cache: JobCache):
    term = args.get("q")
    cache.put("search.unvalidated", term)


def store_non_reaching(args: RequestValues, jobs: JobStore):
    term = args.get("q")
    jobs.put("search.unread", term)
