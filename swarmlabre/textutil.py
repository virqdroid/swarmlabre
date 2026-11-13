"""Small text helpers every module shares: `plain` cleans untrusted text, `scrub` hides secrets in log strings.

`scrub` is pattern-based; a key it cannot recognise (an arbitrary endpoint key) is taught with `register_secret`.
"""
import re

from .reportschema import HIDDEN

SECRET = re.compile(r"(?i)((?:api|admin) key is:\s*)\S+|((?:token|authorization|bearer)\W{0,3})[A-Za-z0-9_\-\.]{16,}")
SECRETS = set()


def register_secret(key):
    """Teach scrub() an exact secret (8 to 512 characters)."""
    if isinstance(key, str) and 8 <= len(key) <= 512:
        SECRETS.add(key)


def scrub(text):
    text = SECRET.sub(lambda m: (m.group(1) or m.group(2)) + "[hidden]", str(text))
    for k in list(SECRETS):
        if k in text:
            text = text.replace(k, "[hidden]")
    return text


def plain(text, limit):
    """Untrusted text as one clean line of at most `limit` characters: control, bidi and zero-width characters become spaces."""
    return HIDDEN.sub(" ", str(text if text is not None else "")).strip()[:limit]
