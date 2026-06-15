def helper():
    return 1


def unused():
    return 2


def recurse(n):
    if n <= 0:
        return 0
    return recurse(n - 1)
