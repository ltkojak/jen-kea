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


def is_secret_key(name) -> bool:
    """True when the VALUE under `name` is a secret and must be masked."""
    if not isinstance(name, str):
        return False
    return bool(
        _SECRET_NAME_RE.search(_CAMEL.sub("_", name.strip()).lower().replace("-", "_"))
    )  # (camelCase reads as snake_case: `clientSecret`, `apiKey`)
