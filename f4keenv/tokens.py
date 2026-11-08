"""Shared, bounded credential-shape generation; no issuer requests."""
import re
import uuid


def value_for(spec, rng):
    if spec['format'] == 'uuid4':
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    if spec['format'] == 'regex':
        from rstr import Xeger
        generator = Xeger(rng)
        pattern = re.compile(spec['pattern'])
        for _ in range(128):
            value = generator.xeger(pattern)
            if 8 <= len(value) <= 2048 and all(33 <= ord(c) < 127 for c in value) and pattern.fullmatch(value):
                return value
        raise ValueError('Could not generate a printable, bounded value: ' + spec['id'])
    if spec['format'] != 'parts':
        raise ValueError('Unsupported generator format: ' + spec['format'])
    return ''.join(part if isinstance(part, str) else ''.join(
        rng.choice(part['alphabet']) for _ in range(part['length'])) for part in spec['parts'])


def near_miss(spec, value):
    for candidate in ('!' + value[1:], '!' + value + '!', value + '!', value[:-1], 'X' + value):
        if candidate and not re.fullmatch(spec['pattern'], candidate):
            return candidate
    raise ValueError('No validated near-miss mutation for ' + spec['id'])
