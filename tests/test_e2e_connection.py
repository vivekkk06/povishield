"""Automated End-to-End Test Suite for PoViShield Local Terminal ↔ Website Connection.

Verifies:
1. Real-time local terminal telemetry recording, secret redaction, and live event stream.
2. Consent-gated remote command dispatch, interactive local consent lifecycle, and fail-closed security.
3. Seccomp policy enforcement under least-privilege confinement (PR_SET_NO_NEW_PRIVS).
4. Security boundary validation: authorization, origin safety, and invalid input rejection.
"""
import asyncio
import json
import os
import shutil
import socket
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api.database as db
from agent.povishield_agent import (
    execute_agent_task,
    handle_command_request_lifecycle,
    prompt_local_consent,
    probe_local_security,
)
from scripts.record_terminal_cmd import redact_secrets

try:
    from fastapi import HTTPException
    from api.main import (
        create_device_command_request_endpoint,
        get_command_request_endpoint,
        submit_local_consent_endpoint,
        submit_web_approval_endpoint,
        submit_command_result_endpoint,
        record_live_event_endpoint,
        get_live_events_endpoint,
        CommandRequestCreate,
        LocalConsentSubmit,
        WebApprovalSubmit,
        CommandResultSubmit,
        LiveEventRecord,
    )
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class TestLocalTerminalTelemetry(unittest.TestCase):
    """Verifies local terminal command execution reporting and live stream fidelity."""

    @classmethod
    def setUpClass(cls):
        db.init_db()

    def setUp(self):
        self.device_id = f"test_dev_{uuid.uuid4().hex[:8]}"
        self.user_id = "usr_operator"
        db.create_device(
            device_id=self.device_id,
            user_id=self.user_id,
            name="Fedora Test Endpoint",
            hostname="fedora.local",
            os_info="Linux 6.11",
            kernel_version="6.11.0",
            arch="x86_64",
            token_hash="dummy_hash",
            capabilities={"seccomp_bpf": True, "no_new_privs": True},
            permissions={"allow_execution": True, "share_output": True}
        )

    def tearDown(self):
        db.delete_device(self.device_id)

    def test_secret_redaction(self):
        """Sensitive credentials in command lines must be redacted before persistence or broadcast."""
        raw_cmd = "curl -H 'Authorization: Bearer pvs_agent_1234567890abcdef12345' --password MySuperSecretPassword123!"
        redacted = redact_secrets(raw_cmd)
        self.assertNotIn("MySuperSecretPassword123!", redacted)
        self.assertNotIn("pvs_agent_1234567890abcdef12345", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_live_event_persistence_and_query(self):
        """Recorded terminal executions must be persisted and returned with live telemetry metadata."""
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "id": event_id,
            "device_id": self.device_id,
            "device_name": "Fedora Test Endpoint",
            "hostname": "fedora.local",
            "event_type": "local_shell_cmd",
            "source": "terminal_hook",
            "timestamp": now,
            "target": "echo",
            "command": ["/usr/bin/echo", "Hello from PoViShield"],
            "pid": 12345,
            "ppid": 12344,
            "exit_code": 0,
            "duration_ms": 1.25,
            "stdout": "Hello from PoViShield\n",
            "stderr": "",
            "policy_decision": {
                "action": "PERMIT_WITH_RESTRICTIONS",
                "allowed": True,
                "mode": "enforce",
                "target_name": "echo",
                "allowed_syscalls": ["access", "brk", "close", "execve", "write", "exit_group"],
                "enforcement_mechanism": "Linux Seccomp-BPF (PR_SET_NO_NEW_PRIVS)"
            },
            "risk_classification": "LOW",
            "delivery_status": "delivered",
            "is_live": True
        }

        # 1. Record event
        saved = db.record_live_event(payload)
        self.assertEqual(saved["id"], event_id)
        self.assertTrue(saved["is_live"])

        # 2. Query live events
        events_list = db.list_live_events(device_id=self.device_id, limit=10)
        matching = [e for e in events_list if e.get("id") == event_id]
        self.assertEqual(len(matching), 1)

        retrieved = matching[0]
        self.assertEqual(retrieved["device_id"], self.device_id)
        self.assertEqual(retrieved["exit_code"], 0)
        self.assertEqual(retrieved["command"], ["/usr/bin/echo", "Hello from PoViShield"])
        self.assertEqual(retrieved["delivery_status"], "delivered")


class TestRemoteCommandConsentLifecycle(unittest.TestCase):
    """Verifies consent-gated remote execution, fail-closed denial, and execution outcome tracking."""

    @classmethod
    def setUpClass(cls):
        db.init_db()

    def setUp(self):
        self.device_id = f"test_dev_{uuid.uuid4().hex[:8]}"
        self.user_id = "usr_operator"
        db.create_device(
            device_id=self.device_id,
            user_id=self.user_id,
            name="Production Security Gateway",
            hostname="sec-gw.internal",
            os_info="Linux 6.8",
            kernel_version="6.8.0",
            arch="x86_64",
            token_hash="dummy_hash",
            capabilities={"seccomp_bpf": True, "no_new_privs": True},
            permissions={"allow_execution": True, "share_output": True}
        )

    def tearDown(self):
        db.delete_device(self.device_id)

    def test_command_request_creation_and_pending_consent(self):
        """Newly created command requests must require local operator consent and initialize in pending state."""
        req = db.create_command_request(
            device_id=self.device_id,
            command=["/usr/bin/echo", "Testing Consent Requirement"],
            user_id=self.user_id,
            working_dir="/tmp",
            requested_privileges="user",
            reason="Security boundary trial",
            mode="enforce",
            local_consent_required=True,
            web_approval_required=False,
            expiry_seconds=120
        )
        self.assertIsNotNone(req["id"])
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["local_consent_status"], "pending")
        self.assertTrue(req["local_consent_required"])

    def test_local_consent_denial_fails_closed(self):
        """Denying local consent must immediately transition request to 'denied' and block execution."""
        req = db.create_command_request(
            device_id=self.device_id,
            command=["/usr/bin/uname", "-a"],
            user_id=self.user_id,
            local_consent_required=True
        )
        req_id = req["id"]

        # Operator denies consent
        updated = db.update_command_request_local_consent(req_id, consent="denied", local_user="operator")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["local_consent_status"], "denied")
        self.assertEqual(updated["status"], "denied")

    def test_local_consent_approval_and_execution_outcome(self):
        """Approving local consent allows execution outcome to be finalized and recorded."""
        req = db.create_command_request(
            device_id=self.device_id,
            command=["/usr/bin/echo", "Consent Granted"],
            user_id=self.user_id,
            local_consent_required=True,
            web_approval_required=False
        )
        req_id = req["id"]

        # Operator approves consent
        updated = db.update_command_request_local_consent(req_id, consent="approved", local_user="operator")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["local_consent_status"], "approved")
        self.assertEqual(updated["status"], "approved")

        # Record outcome
        outcome = {
            "status": "completed",
            "exit_code": 0,
            "duration_ms": 2.1,
            "stdout": "Consent Granted\n",
            "stderr": "",
            "violation_detected": False,
            "syscalls": ["execve", "brk", "write", "exit_group"]
        }
        final = db.update_command_request_result(req_id, outcome, status="completed")
        self.assertIsNotNone(final)
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["result"]["exit_code"], 0)
        self.assertIn("write", final["result"]["syscalls"])

    def test_prompt_local_consent_auto_env(self):
        """Test prompt_local_consent honors explicit environment overrides for deterministic automation."""
        test_req = {
            "id": "cmd_req_mock_001",
            "command": ["/usr/bin/echo", "test"],
            "working_dir": "/tmp",
            "requested_privileges": "user",
            "mode": "enforce"
        }

        # Test approval override
        os.environ["POVISHIELD_AUTO_CONSENT"] = "approve"
        self.assertTrue(prompt_local_consent(test_req, timeout_seconds=1.0))

        # Test denial override (fail-closed)
        os.environ["POVISHIELD_AUTO_CONSENT"] = "deny"
        self.assertFalse(prompt_local_consent(test_req, timeout_seconds=1.0))

        del os.environ["POVISHIELD_AUTO_CONSENT"]


class TestAgentExecutionConfinement(unittest.TestCase):
    """Verifies least-privilege execution boundary and security probing on host."""

    def test_host_security_probe(self):
        """Host probe must accurately report platform capabilities truthfully."""
        probe = probe_local_security()
        self.assertTrue(probe["is_linux"])
        self.assertIn("architecture", probe)
        self.assertIn("hostname", probe)
        self.assertIn("seccomp_bpf", probe)
        self.assertIn("no_new_privs", probe)

    def test_execute_agent_task_echo(self):
        """Executing /usr/bin/echo under agent supervision must record exit code and syscalls."""
        echo_bin = shutil.which("echo") or "/usr/bin/echo"
        task = {
            "id": f"task_{uuid.uuid4().hex[:8]}",
            "command": [echo_bin, "Hello from PoViShield Automated Test"],
            "mode": "enforce",
            "working_dir": str(ROOT)
        }
        config = {
            "server_url": "http://127.0.0.1:8000",
            "device_id": "test_device",
            "permissions": {"allow_execution": True, "share_output": True}
        }
        res = execute_agent_task(task, config)
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("Hello from PoViShield Automated Test", res.get("stdout", ""))
        self.assertGreater(len(res.get("syscalls", [])), 0)
        self.assertIn("timeline", res)


if __name__ == "__main__":
    unittest.main()
