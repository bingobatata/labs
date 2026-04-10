"""Tests for portscanner.py — focused on finding missed-port bugs."""

import asyncio
import socket
import threading
import time
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from portscanner import fast_sweep, parse_ports, probe


# ── parse_ports ──────────────────────────────────────────────────────────

class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_range(self):
        assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]

    def test_csv(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

    def test_dedup(self):
        assert parse_ports("80,80,80") == [80]

    def test_out_of_range_filtered(self):
        assert parse_ports("0,1,65535,65536") == [1, 65535]

    def test_full_range_count(self):
        assert len(parse_ports("1-65535")) == 65535

    def test_spaces(self):
        assert parse_ports(" 22 , 80 ") == [22, 80]


# ── probe ────────────────────────────────────────────────────────────────

class TestProbe:
    @pytest.mark.asyncio
    def test_open_port_returns_port(self):
        """probe() should return the port number when connection succeeds."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)
        try:
            sem = asyncio.Semaphore(10)
            result = asyncio.run(probe("127.0.0.1", port, 2.0, sem))
            assert result == port
        finally:
            sock.close()

    @pytest.mark.asyncio
    def test_closed_port_returns_none(self):
        """probe() should return None for a closed port."""
        # Bind then close to get a port that is almost certainly closed
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        sem = asyncio.Semaphore(10)
        result = asyncio.run(probe("127.0.0.1", port, 0.5, sem))
        assert result is None

    @pytest.mark.asyncio
    def test_timeout_returns_none(self):
        """probe() should return None when connection times out."""
        sem = asyncio.Semaphore(10)
        # Use a non-routable IP to trigger timeout
        result = asyncio.run(probe("192.0.2.1", 1, 0.3, sem))
        assert result is None


# ── fast_sweep — real sockets ────────────────────────────────────────────

class TestFastSweep:
    def _listen_server(self, ports):
        """Open listener sockets on each port, return (sockets, actual_ports)."""
        socks = []
        actual_ports = []
        for _ in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(5)
            actual_ports.append(s.getsockname()[1])
            socks.append(s)
        return socks, actual_ports

    def test_finds_all_open_ports(self):
        """The sweep must not miss any port that is listening."""
        socks, expected = self._listen_server(range(20))
        try:
            found = asyncio.run(
                fast_sweep("127.0.0.1", expected, concurrency=50, timeout=2.0)
            )
            assert sorted(found) == sorted(expected), (
                f"Missed ports: {set(expected) - set(found)}"
            )
        finally:
            for s in socks:
                s.close()

    def test_no_false_positives_on_closed(self):
        """Closed ports must not appear in results."""
        # Get ports that are definitely closed
        closed = []
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            closed.append(port)
        found = asyncio.run(
            fast_sweep("127.0.0.1", closed, concurrency=50, timeout=0.5)
        )
        assert found == []

    def test_mixed_open_and_closed(self):
        """Only open ports should be returned, not closed ones."""
        socks, open_ports = self._listen_server(range(5))
        # Grab 5 closed ports
        closed = []
        for _ in range(5):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            closed.append(s.getsockname()[1])
            s.close()
        try:
            all_ports = open_ports + closed
            found = asyncio.run(
                fast_sweep("127.0.0.1", all_ports, concurrency=50, timeout=2.0)
            )
            assert sorted(found) == sorted(open_ports)
        finally:
            for s in socks:
                s.close()

    def test_high_concurrency_no_missed_ports(self):
        """
        Regression: with concurrency higher than port count, ensure no ports
        are dropped. This tests the semaphore / task-collection logic.
        """
        socks, expected = self._listen_server(range(30))
        try:
            found = asyncio.run(
                fast_sweep("127.0.0.1", expected, concurrency=5000, timeout=2.0)
            )
            assert sorted(found) == sorted(expected)
        finally:
            for s in socks:
                s.close()

    def test_low_concurrency_no_missed_ports(self):
        """
        With concurrency=1 (sequential), every open port must still be found.
        This is the scenario most likely to interact badly with semaphore bugs.
        """
        socks, expected = self._listen_server(range(10))
        try:
            found = asyncio.run(
                fast_sweep("127.0.0.1", expected, concurrency=1, timeout=2.0)
            )
            assert sorted(found) == sorted(expected)
        finally:
            for s in socks:
                s.close()


# ── Simulated flaky / edge-case probes ───────────────────────────────────

class TestProbeEdgeCases:
    def test_connection_reset_returns_none(self):
        """A port that RSTs after accept should not crash the scanner."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def rst_server():
            conn, _ = srv.accept()
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"
            )
            conn.close()

        t = threading.Thread(target=rst_server)
        t.start()
        sem = asyncio.Semaphore(10)
        # The port IS open (we connect successfully), so it should still be returned
        result = asyncio.run(probe("127.0.0.1", port, 2.0, sem))
        t.join()
        srv.close()
        # Connection succeeds before the RST, so port should be reported open
        assert result == port

    def test_slow_accept_within_timeout(self):
        """A port that is slow to accept but within timeout should be found."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)
        # accept in background after a short delay
        def delayed_accept():
            time.sleep(0.3)
            conn, _ = srv.accept()
            conn.close()

        t = threading.Thread(target=delayed_accept)
        t.start()
        sem = asyncio.Semaphore(10)
        result = asyncio.run(probe("127.0.0.1", port, 3.0, sem))
        t.join()
        srv.close()
        assert result == port


# ── Retry logic ──────────────────────────────────────────────────────────

class TestRetries:
    def test_retry_succeeds_after_transient_failure(self):
        """Port that fails once then succeeds should be found with retries."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(5)

        call_count = 0
        _real_open = asyncio.open_connection

        async def flaky_open(host, p):
            nonlocal call_count
            if p == port:
                call_count += 1
                if call_count == 1:
                    raise OSError("simulated resource exhaustion")
            return await _real_open(host, p)

        try:
            sem = asyncio.Semaphore(10)
            with patch("portscanner.asyncio.open_connection", side_effect=flaky_open):
                result = asyncio.run(probe("127.0.0.1", port, 2.0, sem, retries=2))
            assert result == port, "Port should be found after retry"
            assert call_count >= 2, "Should have retried at least once"
        finally:
            srv.close()

    def test_no_retry_on_connection_refused(self):
        """ConnectionRefusedError means port is closed — no retry needed."""
        call_count = 0

        async def refused_open(host, p):
            nonlocal call_count
            call_count += 1
            raise ConnectionRefusedError()

        sem = asyncio.Semaphore(10)
        with patch("portscanner.asyncio.open_connection", side_effect=refused_open):
            result = asyncio.run(probe("127.0.0.1", 9999, 1.0, sem, retries=3))
        assert result is None
        assert call_count == 1, "Should NOT retry on ConnectionRefusedError"

    def test_retries_zero_disables(self):
        """With retries=0, a single failure should give up immediately."""
        call_count = 0

        async def fail_open(host, p):
            nonlocal call_count
            call_count += 1
            raise OSError("fail")

        sem = asyncio.Semaphore(10)
        with patch("portscanner.asyncio.open_connection", side_effect=fail_open):
            result = asyncio.run(probe("127.0.0.1", 9999, 1.0, sem, retries=0))
        assert result is None
        assert call_count == 1

    def test_retries_exhaust_returns_none(self):
        """If all retries fail, probe returns None."""
        call_count = 0

        async def always_fail(host, p):
            nonlocal call_count
            call_count += 1
            raise OSError("persistent failure")

        sem = asyncio.Semaphore(10)
        with patch("portscanner.asyncio.open_connection", side_effect=always_fail):
            result = asyncio.run(probe("127.0.0.1", 9999, 1.0, sem, retries=2))
        assert result is None
        assert call_count == 3, "Should attempt 1 + 2 retries = 3 total"

    def test_sweep_with_retries_finds_all(self):
        """fast_sweep with retries should still find all open ports."""
        socks = []
        ports = []
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(5)
            ports.append(s.getsockname()[1])
            socks.append(s)
        try:
            found = asyncio.run(
                fast_sweep("127.0.0.1", ports, concurrency=50, timeout=2.0,
                           retries=2)
            )
            assert sorted(found) == sorted(ports)
        finally:
            for s in socks:
                s.close()
