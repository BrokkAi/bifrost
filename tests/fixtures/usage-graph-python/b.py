from a import helper


# Module-level call site: its enclosing scope is not a class or function, so
# this reference must not produce an edge from a non-node.
TOP = helper()


def run():
    return helper()


def run_twice():
    first = helper()
    second = helper()
    return first + second


def shadowed_param(helper):
    # `helper` is the parameter, not the imported `a.helper`; this call must not
    # produce a shadowed_param -> a.helper edge.
    return helper()


def shadowed_local():
    # A local assignment shadows the import for the rest of the function, so the
    # call below resolves to the local, not `a.helper`.
    helper = lambda: 0
    return helper()
