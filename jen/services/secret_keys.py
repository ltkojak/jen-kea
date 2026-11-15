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
    r"(^|_)(password|passwd|passphrase|pass_phrase|pass|pwd|secrets?|secret_key|tokens?|api_keys?|apikeys?|private_key|authorization|credentials?)\d*$"
)  # (Q225, AK16) `pass_phrase` and the singular `credential` beside the forms that were already here; (Q226, AL17) the plurals `secrets`, `tokens`, `api_keys`, and a trailing number
# (`password2`). An all-upper-case run with no boundary (`DBPASSWORD`) stays outside the rule on purpose: the rule is "ends in a secret word", and a word boundary is what makes a word
_CAMEL = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
)  # (Q225, AK16) a word boundary also falls inside an upper-case run before its last letter: `DBPassword` is `DB_Password`, `SMTPPass` is `SMTP_Pass`
_SPACES = re.compile(
    r"\s+"
)  # (Q224, AJ13) `Client Secret` is `client_secret`: a space is a word boundary like `-` and `_`


def is_secret_key(name) -> bool:
    """True when the VALUE under `name` is a secret and must be masked."""
    if not isinstance(name, str):
        return False
    return bool(
        _SECRET_NAME_RE.search(
            _SPACES.sub("_", _CAMEL.sub("_", name.strip()).lower().replace("-", "_").replace(".", "_"))
        )
    )  # (camelCase reads as snake_case: `clientSecret`, `apiKey`; a spaced or a dotted name as a snake_case one: `Client Secret`, `smtp.password` - Q225, AK16)


_PADDING = " \t\r\n"
# (Q190 second pass, finding 5: the user-info runs to the LAST '@' before the path - a password may contain one - so the pattern is greedy up to a delimiter. Q221, AE7: a quote or an angle
# bracket is NOT a delimiter - a password may contain those too - so an address ends at whitespace, `/`, `?` or `#` and nowhere else; over-scrubbing a sentence is the safe direction)
_USERINFO_RE = re.compile(r"(?i)\b(https?://)[^\s/?#]*@")
# (Q237) an address inside a text, for `without_credentials`: a scheme, `://` and everything up to the next white space
_ADDRESS_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")
_MASK = "********"


def _masked_query(query: str) -> str:
    """Every parameter of a query with its value masked and its name kept; a parameter that is a bare word is masked whole. (Q237, the independent review's #3) Only a
    value under a secret's NAME used to go, and a signature is a secret under any name: `sig`, `X-Amz-Signature`, `se`, a name nobody has listed."""
    out = []
    for pair in query.split("&"):
        name, eq, held = pair.partition("=")
        out.append(f"{name}={_MASK}" if eq and held else (_MASK if pair and not eq else pair))
    return "&".join(out)


def _address_without_credentials(address: str, query: bool = True) -> str:
    """One address without its user-info and, with `query`, with every query value masked; as written when it has neither or cannot be split. The fragment is
    kept (Q238): it is the part of an address that is never sent to a server, and in a configuration it is an anchor in a manual."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(address)
    except ValueError:
        return address
    netloc = parts.netloc.rsplit("@", 1)[1] if "@" in parts.netloc else parts.netloc
    masked = _masked_query(parts.query) if query and parts.query else parts.query
    if not parts.scheme or (netloc, masked) == (parts.netloc, parts.query):
        return address
    return urlunsplit(parts._replace(netloc=netloc, query=masked))


def without_credentials(value) -> str:
    """A string VALUE of a configuration as a page may show it (Q230, AP9 and the beta.15 review's #2; CRED-005 at the display). The places a secret sits inside an
    address that `without_userinfo` does not reach: the user-info of an address whose scheme is not http(s) (`ldap://u:pw@h`, `postgresql://`, `redis://`, `wss://` -
    the authority of ANY scheme `urlsplit` reads a host from is split at its LAST `@`), and the VALUE of every query parameter, which keeps its name (Q237: a signed
    address carries its secret under any name). The value is read twice. Whole, as ONE address, for its USER-INFO only: a password with a space in it goes, which no
    pattern over a text can promise. Then every address inside it, each ending at the next white space, for its user-info and its query.
    (Q238, AW3) The whole-value read used to mask the query too, and `urlsplit` over a whole value puts everything after its first `?` or `#` into the query or the
    fragment: a second address, the rest of a sentence and the next two lines of a three-line value were replaced by one mask, and two revisions that differed only
    there were shown as the same. Nothing but a user-info and a query VALUE is removed now, and a fragment is kept. The stated limit: a query value written with a
    literal space in it is masked up to that space.
    Everything else is returned as written; what is left goes through `scrub_urls`. Idempotent. A value with no `://` is not read as an address: `user:pw@host`
    is also how a SIP or a mail address is written, and a rule that cannot tell them apart is not applied. This masks a COPY for display; the configuration it
    was read from is never written from it."""
    text = str(value if value is not None else "")
    if "://" not in text:
        return scrub_urls(text)
    stripped = text.strip(_PADDING)
    whole = _address_without_credentials(stripped, query=False)
    if whole != stripped:
        text = whole
    return scrub_urls(_ADDRESS_RE.sub(lambda found: _address_without_credentials(found.group(0)), text))


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
