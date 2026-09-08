"""
jen/wsgi.py
───────────
The WSGI entrypoint gunicorn loads: `gunicorn jen.wsgi:application`.

`run.py` builds the gunicorn command line and launches it (see there
for the process model). This module is imported once per gunicorn
worker — and Jen runs `--workers 1` — so the module-level
`start_background_workers()` call starts the scheduler and alert loop
exactly once for the running instance.

Logging is configured twice on purpose, mirroring what `run.py` did
before: once from env only (so anything logged during `create_app()`
is formatted), then again once `extensions.cfg` is populated so the
file-based `[server]` log settings take effect.
"""

from jen import create_app, extensions
from jen.logging_config import configure_logging
from jen.services.background import start_background_workers

configure_logging()
application = create_app()
configure_logging(extensions.cfg)

start_background_workers(application)
