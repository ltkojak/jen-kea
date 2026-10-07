"""
tests/test_alert_log_retention.py
─────────────────────────────────
v5.68.0-beta.17 (Q152, item c) - `alert_log` was the one history table nothing pruned. Rows older than `alert_log_retention_days`
(default 180) are removed by the same job as the other history tables, the Alert Log page says how long a row is kept, and the
Prometheus counter built from the table never goes down because of it (what is removed is counted into a stored total first).
"""
