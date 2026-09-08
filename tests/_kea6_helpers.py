"""Shared fakes for the test_kea6_* / test_kea_authoring suites (split out of test_kea6.py in v5.6.1 — it was used across the service-toggle, subnet-edit, and config-authoring areas)."""


class FakeSSHClient:
    """Stand-in for paramiko.SSHClient that records exec_command calls and
    returns scripted stdout/stderr per call, in order. Each response is
    (out, err) or (out, err, exit_status) — exit_status defaults to 0
    when omitted, for the (large majority of) existing tests that only
    care about stdout content."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.closed = False

    def exec_command(self, cmd):
        self.calls.append(cmd)
        resp = self._responses.pop(0) if self._responses else ("", "")
        if len(resp) == 3:
            out, err, exit_status = resp
        else:
            out, err = resp
            exit_status = 0

        class _Channel:
            def __init__(self, status):
                self._status = status

            def recv_exit_status(self):
                return self._status

        class _Stream:
            def __init__(self, text, channel=None):
                self._text = text
                self.channel = channel

            def read(self):
                return self._text.encode()

        channel = _Channel(exit_status)
        return None, _Stream(out, channel), _Stream(err, channel)

    def close(self):
        self.closed = True
