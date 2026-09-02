"""Load operator-supplied settings for the report tool."""

import pickle


def load_overrides(path):
    with open(path, "rb") as handle:
        return pickle.loads(handle.read())


def apply_expression(row, expression):
    return eval(expression, {"row": row})
