"""Bounded word transcripts and correction vectors for the independent reference."""

import random

import contribution_reference as model


def fixture(index):
    return (0x50594F42, 0x1000 + index, 0x2000 + index,
        [(0xA100 + index, 0x2001, [0x1234ABCD, 0x9876EF01 ^ index, 0xFFFFFFFF - index]),
         (0xB100 + index, 0x1001, [0, 0x80000000 + index])])


def final(case):
    domain, function, site, sources = case
    state = model.initialize(domain, function, site)
    for label, encoding, words in sources:
        state = model.source(state, label, encoding, len(words))
        for word in words: state = model.word(state, word)
    return model.finish(state)


def write_vectors(path):
    if (model.VERSION != 1 or model.initialize(0, 0, 0) != (1236985088, 3898519529, 1) or
            model.finish(model.initialize(0, 0, 0)) != 4207804400 or
            model.absorb(model.initialize(0, 0, 0), 0, 0) != (2102959130, 1436023554, 2)):
        raise AssertionError("contribution v1 pinned arithmetic changed")
    randomizer = random.Random(0x6E34A129)
    boundary = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555]
    cases = [fixture(index) for index in range(3)]
    cases += [(value, value, value, [(value, value, boundary)]) for value in boundary]
    for index in range(128):
        cases.append((*[randomizer.getrandbits(32) for _ in range(3)],
            [(randomizer.getrandbits(32), randomizer.getrandbits(32),
              [randomizer.getrandbits(32) for _ in range((index + source) % 9)]) for source in range(index % 5)]))
    base = fixture(0)
    domain, function, site, sources = base
    changed = [(domain ^ 1, function, site, sources), (domain, function ^ 1, site, sources),
               (domain, function, site ^ 1, sources), (domain, function, site, list(reversed(sources)))]
    for index, (label, encoding, words) in enumerate(sources):
        changed.append((domain, function, site, sources[:index] + sources[index + 1:]))
        changed.append((domain, function, site, sources[:index] + [sources[index]] + sources[index:]))
        for replacement in ((label ^ 1, encoding, words), (label, encoding ^ 1, words)):
            changed.append((domain, function, site, sources[:index] + [replacement] + sources[index + 1:]))
        for word in range(len(words)):
            for bit in range(32):
                values = list(words); values[word] ^= 1 << bit
                changed.append((domain, function, site, sources[:index] + [(label, encoding, values)] + sources[index + 1:]))
    if any(final(case) == final(base) for case in changed):
        raise AssertionError("named owner/site/encoding/order/source/data mutation did not perturb contribution")
    cases += changed
    framed = [(1, 2, 3, []), (1, 2, 3, [(4, 5, [])]),
              (1, 2, 3, [(4, 5, [6, 7])]), (1, 2, 3, [(4, 5, [6]), (4, 5, [7])])]
    if len({final(case) for case in framed}) != len(framed):
        raise AssertionError("source count/length framing collapsed distinct source groups")
    cases += framed
    lines = [str(len(cases))]
    for domain, function, site, sources in cases:
        state = model.initialize(domain, function, site)
        lines += [f"{domain} {function} {site} {len(sources)}", " ".join(map(str, state))]
        for label, encoding, words in sources:
            state = model.source(state, label, encoding, len(words))
            lines += [f"{label} {encoding} {len(words)}", " ".join(map(str, state))]
            for word in words:
                state = model.word(state, word)
                lines.append(" ".join(map(str, (word, *state))))
        lines.append(str(model.finish(state)))
    bindings = 0
    for index in range(3):
        current, target = 0x13579BDF + index * 0x10203, 0x2468ACE0 ^ (index * 0x9E37)
        expected, salt, transition_salt = final(fixture(index)), 0x73A92E11 + index * 17, 0x5A91C37D ^ (index * 0x101)
        encoded = ((target - current) & model.MASK) ^ model.mix(current ^ transition_salt)
        sealed = model.seal(encoded, expected, salt)
        values = [(current, expected), *[(current, expected ^ (1 << bit)) for bit in range(32)],
                  *[(current ^ (1 << bit), expected) for bit in range(32)]]
        values += [(current, value) for value in boundary]
        values += [(current, randomizer.getrandbits(32)) for _ in range(512)]
        lines.append(f"{current} {target} {expected} {salt} {transition_salt} {len(values)}")
        for state, observed in values:
            delta = model.unseal(sealed, observed, salt) ^ model.mix(state ^ transition_salt)
            if state == current and (delta == ((target - current) & model.MASK)) != (observed == expected):
                raise AssertionError("fixed-state correction lost its actual observation dependency")
            lines.append(f"{state} {observed} {delta}")
        bindings += len(values)
    for count in (1, 2, 3):
        rows = [tuple(randomizer.getrandbits(32) for _ in range(3)) for _ in range(128)]
        rows += [(word, word, word) for word in boundary]
        lines.append(str(len(rows)))
        for words in rows:
            value = final((77, 13, 101, [(17 + index * 12, 1, [words[index]]) for index in range(count)]))
            lines.append(" ".join(map(str, (*words, value))))
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    for bad in (-1, 1 << 32, True, 1.0):
        for operation in (lambda: model.initialize(bad, 0, 0), lambda: model.word((0, 0, 0), bad),
                          lambda: model.source((0, 0, 0), 1, 1, bad), lambda: model.seal(0, bad, 0)):
            try: operation()
            except ValueError: pass
            else: raise AssertionError("malformed contribution word was truncated")
    for bad in ((), (0, 0), (0, 0, 0, 0), None):
        try: model.finish(bad)
        except ValueError: pass
        else: raise AssertionError("malformed contribution state was accepted")
    return len(cases), len(changed), bindings
