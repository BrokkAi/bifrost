def identical(value):
    if value == value:  # positive: identical expressions
        return True
    return False


def different(left, right):
    if left == right:  # near miss: distinct expressions
        return True
    return False


class Holder:
    def same_path(self):
        if self.value == self.value:  # positive: same binding and attribute path
            return True
        return False

    def different_roots(self, left, right):
        if left.value == right.value:  # near miss: different root bindings
            return True
        return False

    def different_members(self):
        if self.left == self.right:  # near miss: different attribute paths
            return True
        return False


def nan_calls_are_not_constant_expressions():
    if float("nan") == float("nan"):  # near miss: NaN-sensitive computed values
        return True
    return False
