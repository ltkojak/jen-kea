"""
jen/services/secret_keys.py
───────────────────────────
ONE definition of "this key's VALUE is a secret" (Q204 AT4, LEAK-001).

Two lists used to say it: the Kea-config masker (`kea_authoring.redact_secrets`: the config-history diff and download, the authoring preview) knew
`password`, `secret`, `basic-auth-password` and the `-password` / `_password` / `-secret` suffixes, and the support bundle's INI mask knew `pass`,
`passwd`, `token`, `api_key`, `client_secret`, `metrics_token` and `_pass` / `_token` - so a `token`, an `api-key` or a `passwd` in a hook library's
parameters passed in clear into the diff a non-superadmin reads, and a `-secret` passed into the bundle. Both callers call this function; a new masker that
decides by a key NAME calls it too (`tests/test_secret_keys.py` fails a second list in `jen/`).

A hyphen and an underscore read alike and the case is ignored. A key that names a PATH to a secret (`password-file`, `key_path`, `api_client_key`, `ssl_key`,
`cert-file`) is never a secret: it does not END in one of the words below, which is the whole rule - the path is diagnostic, the file is never opened.
"""

import re

# a bare secret word, or a name that ends in one after an underscore: `smtp_password`, `basic_auth_password`, `client_secret`, `metrics_token`, `api_token`,
# `api_pass`, `db_passwd`, and `api_key` (the one two-word secret: a bare `key` is not one - `ssl_key` and `api_client_key` name files)
_SECRET_NAME_RE = re.compile(
    r"(^|_)(password|passwd|passphrase|pass|pwd|secret|secret_key|token|api_key|apikey|private_key|authorization|credentials)$"
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPACES = re.compile(
    r"\s+"
)  # (Q224, AJ13) `Client Secret` is `client_secret`: a space is a word boundary like `-` and `_`


def is_secret_key(name) -> bool:
    """True when the VALUE under `name` is a secret and must be masked."""
    if not isinstance(name, str):
        return False
    return bool(
        _SECRET_NAME_RE.search(_SPACES.sub("_", _CAMEL.sub("_", name.strip()).lower().replace("-", "_")))
    )  # (camelCase reads as snake_case: `clientSecret`, `apiKey`; a spaced name as a snake_case one: `Client Secret`)


_PADDING = " \t\r\n"
# (Q190 second pass, finding 5: the user-info runs to the LAST '@' before the path - a password may contain one - so the pattern is greedy up to a delimiter. Q221, AE7: a quote or an angle
# bracket is NOT a delimiter - a password may contain those too - so an address ends at whitespace, `/`, `?` or `#` and nowhere else; over-scrubbing a sentence is the safe direction)
_USERINFO_RE = re.compile(r"(?i)\b(https?://)[^\s/?#]*@")


def scrub_urls(text) -> str:
    """`text` with the user-info of every http(s) address in it removed (`https://u:p@h:8004/x` -> `https://h:8004/x`): for TEXT that may carry an address as it was typed - an exception's message, a
    log line, a sentence. Idempotent; a text with no address comes back unchanged. THE definition (Q221, AE7); `auth.scrub_urls` is this."""
    return _USERINFO_RE.sub(r"\1", str(text if text is not None else ""))


def without_userinfo(value) -> str:
    """A value that IS one address - a saved `api_url`, a Kea `url` key, a form field - without its user-info, whatever characters the user-info carries (Q221, AE7; CRED-005). The authority is split
    by `urlsplit` at its LAST `@`, so a password with a space in it goes too, which no pattern over free text can promise; what is left goes through `scrub_urls`. A value that is not an http(s)
    address is `scrub_urls` of it. Idempotent. The exported layer (the support bundle) and the compare's sentence use this for a value; `auth.without_userinfo` is this."""
    from urllib.parse import urlsplit, urlunsplit

    text = str(value if value is not None else "")
    try:
        parts = urlsplit(text.strip(_PADDING))
        if parts.scheme.lower() in ("http", "https") and "@" in parts.netloc:
            text = urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))
    except ValueError:
        pass
    return scrub_urls(text)
