class Service:
    def handle(self):
        return 1


def run(s: Service):
    # `s` is typed as Service; the forward scan_usages path resolves the
    # receiver and finds this call, but the inverted usage_graph path currently
    # lacks receiver typing and misses the run -> Service.handle edge.
    return s.handle()
