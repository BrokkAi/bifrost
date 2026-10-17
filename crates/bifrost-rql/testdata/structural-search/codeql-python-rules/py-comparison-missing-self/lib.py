item = 1


class Example:
    def __init__(self, item):
        self.item = item

    def missing_self(self):
        if item == item:  # positive: likely omitted self.item
            return True
        return False

    def local_binding(self):
        item = 1
        if item == item:  # near miss: method-local binding exists
            return True
        return False

    def parameter_binding(self, item):
        if item == item:  # near miss: parameter binding exists
            return True
        return False

    def explicit_global(self):
        global item
        if item == item:  # near miss: explicit global directive
            return True
        return False


def enclosing_scope():
    item = 1

    class NestedExample:
        def __init__(self):
            self.item = item

        def explicit_nonlocal(self):
            nonlocal item
            if item == item:  # near miss: explicit nonlocal directive
                return True
            return False


def distinct(left, right):
    if left == right:  # near miss: operands are distinct bindings
        return True
    return False
