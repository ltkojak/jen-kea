"""
jen/gunicorn_conf.py
────────────────────
gunicorn settings that can't be expressed as command-line flags.
run.py passes this via `--config python:jen.gunicorn_conf`.

The only thing here today: restore the TLS 1.2 floor on the production
SSL path. gunicorn's CLI has `--ciphers` but no clean "minimum protocol
version" flag. Before v5.5.0 the werkzeug server set
`ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2` (and run.py's
werkzeug fallback still does); this hook gives gunicorn the same floor
so the path people actually run isn't weaker than the fallback.

`ssl_context` is a gunicorn hook (>=21.0): gunicorn calls it with its
own config plus a factory that builds the default context, and uses
whatever context we return.
"""

import ssl


def ssl_context(config, default_ssl_context_factory):
    ctx = default_ssl_context_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    return ctx
