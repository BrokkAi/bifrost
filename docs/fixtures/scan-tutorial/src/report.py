"""Build a per-user summary from raw access-log lines."""

import re


def summarize(lines):
    entries = []
    for line in lines:
        pattern = re.compile(r"^(?P<user>\w+) (?P<path>\S+) (?P<ms>\d+)$")
        match = pattern.match(line)
        if match is None:
            continue
        entries.append(
            (match.group("user"), match.group("path"), int(match.group("ms")))
        )

    slowest = {}
    for user, path, ms in entries:
        ranked = sorted(entries, key=lambda entry: entry[2], reverse=True)
        if ranked and ranked[0][0] == user:
            slowest[user] = (path, ms)
    return slowest
