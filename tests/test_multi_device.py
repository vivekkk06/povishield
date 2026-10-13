"""Automated Test Suite for PoViShield Multi-Device Fleet Platform:

Pairing, Authentication, Ownership Isolation, Rate Limiting, Revocation, and Remote Task Execution.
"""
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api.database as db
from agent.povishield_agent import (
    execute_agent_task,
    pair_agent,
    probe_local_security,
)
from api.auth import hash_token

try:
    from fastapi import HTTPException
    from api.main import (
        AgentEventsRequest,
        AgentHeartbeatRequest,
        AgentPairRequest,
        AgentTaskResultRequest,
        DeviceTaskCreateRequest,
        PairingGenerateRequest,
        agent_disconnect_endpoint,
        agent_events_endpoint,
        agent_heartbeat_endpoint,
        agent_pair_endpoint,
        agent_task_result_endpoint,
        create_device_task,
        delete_device_endpoint,
        generate_pairing_code,
        get_agent_script,
        get_device_details,
        get_device_events_endpoint,
        get_device_task,
        get_install_script,
        list_devices,
        revoke_device_endpoint,
    )
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    HTTPException = Exception  # type: ignore


def make_req(headers=None, host="127.0.0.1"):
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        headers=headers or {}
    )


class TestMultiDeviceFleet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HAS_FASTAPI:
            raise unittest.SkipTest("FastAPI not installed in current Python environment (run in .venv or via check_web.sh)")
        cls.test_db = ROOT / "results" / "test_fleet.db"
        if cls.test_db.exists():
            cls.test_db.unlink()
        os.environ["POVISHIELD_DATABASE_URL"] = f"sqlite:///{cls.test_db}"
        db.init_db()

    def setUp(self):
        conn = db.get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM pairing_rate_limits;")
        finally:
            conn.close()

    @classmethod
    def tearDownClass(cls):
        if cls.test_db.exists():
            try:
                cls.test_db.unlink()
            except OSError:
                pass

    def test_01_probe_truthful_capabilities(self):
        """Probes real Linux kernel capabilities without simulation."""
        probe = probe_local_security()
        self.assertIn("is_linux", probe)
        self.assertIn("seccomp_bpf", probe)
        self.assertIn("no_new_privs", probe)
        self.assertIn("native_sandbox", probe)
        self.assertIn("enforcement_verified", probe)
        if sys.platform.startswith("linux"):
            self.assertTrue(probe["is_linux"])
            self.assertTrue(probe["seccomp_bpf"])

    def test_02_pairing_code_generation(self):
        """Generates single-use pairing code with TTL."""
        req = make_req(headers={"host": "127.0.0.1:8000"})
        data = generate_pairing_code(PairingGenerateRequest(device_name_hint="Dev-01"), req)
        self.assertTrue(data["code"].startswith("PVS-"))
        self.assertEqual(data["expires_in_seconds"], 600)
        self.assertIn("install_command", data)
        self.assertIn("cli_command", data)

    def test_03_pairing_code_single_use(self):
        """Pairing code is atomically consumed and cannot be reused."""
        req = make_req(host="127.0.0.1")
        gen = generate_pairing_code(PairingGenerateRequest(), req)
        code = gen["code"]

        payload = AgentPairRequest(
            pairing_code=code,
            name="Host-Alpha",
            hostname="alpha-box",
            os_info="Linux 6.x",
            kernel_version="6.12.0",
            arch="x86_64",
            capabilities={"seccomp_bpf": True, "native_sandbox": True},
            permissions={"allow_execution": True, "share_output": True}
        )

        # 1st pair: succeeds
        data1 = agent_pair_endpoint(payload, req)
        self.assertEqual(data1["status"], "paired")
        self.assertTrue(data1["device_id"].startswith("dev_"))
        self.assertTrue(data1["token"].startswith("pvs_agent_"))

        # 2nd pair with same code: fails (already consumed)
        with self.assertRaises(HTTPException) as ctx:
            agent_pair_endpoint(payload, req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("already been consumed", ctx.exception.detail)

    def test_04_pairing_code_expiration(self):
        """Expired pairing codes fail closed."""
        req = make_req(host="127.0.0.1")
        gen = generate_pairing_code(PairingGenerateRequest(expires_in_seconds=60), req)
        code = gen["code"]

        # Artificially expire the code in DB
        conn = db.get_connection()
        try:
            with conn:
                conn.execute("UPDATE pairing_codes SET expires_at = '2020-01-01T00:00:00+00:00' WHERE code = ?", (code,))
        finally:
            conn.close()

        payload = AgentPairRequest(
            pairing_code=code,
            name="Host-Expired",
            hostname="expired-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        )
        with self.assertRaises(HTTPException) as ctx:
            agent_pair_endpoint(payload, req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("expired", ctx.exception.detail.lower())

    def test_05_pairing_rate_limiting(self):
        """Rate limiting prevents brute force on pairing endpoint."""
        test_ip = "198.51.100.77"
        for _ in range(5):
            db.check_pairing_rate_limit(test_ip, max_attempts=5, window_seconds=60)

        # 6th attempt is blocked
        req = make_req(host=test_ip)
        payload = AgentPairRequest(
            pairing_code="PVS-FAKE",
            name="Host-Brute",
            hostname="brute-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        )
        with self.assertRaises(HTTPException) as ctx:
            agent_pair_endpoint(payload, req)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_06_authenticated_heartbeat(self):
        """Agent heartbeat requires valid Bearer token."""
        req = make_req(host="127.0.0.1")
        gen = generate_pairing_code(PairingGenerateRequest(), req)
        pair_res = agent_pair_endpoint(AgentPairRequest(
            pairing_code=gen["code"],
            name="Host-Heartbeat",
            hostname="hb-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        ), req)
        token = pair_res["token"]
        device_id = pair_res["device_id"]

        # 1. Unauthenticated heartbeat -> 401
        with self.assertRaises(HTTPException) as ctx1:
            agent_heartbeat_endpoint(AgentHeartbeatRequest(device_id=device_id), make_req())
        self.assertEqual(ctx1.exception.status_code, 401)

        # 2. Invalid token -> 401
        with self.assertRaises(HTTPException) as ctx2:
            agent_heartbeat_endpoint(
                AgentHeartbeatRequest(device_id=device_id),
                make_req(headers={"authorization": "Bearer bad_token"})
            )
        self.assertEqual(ctx2.exception.status_code, 401)

        # 3. Valid token -> 200 OK
        hb = agent_heartbeat_endpoint(
            AgentHeartbeatRequest(device_id=device_id),
            make_req(headers={"authorization": f"Bearer {token}"})
        )
        self.assertEqual(hb["status"], "ack")
        self.assertEqual(hb["device_id"], device_id)

    def test_07_multi_user_ownership_isolation(self):
        """User B cannot inspect, control, or dispatch tasks to User A's device."""
        req_alice = make_req(headers={"x-povishield-user": "alice"})
        req_bob = make_req(headers={"x-povishield-user": "bob"})

        # Alice creates a device
        gen_a = generate_pairing_code(PairingGenerateRequest(), req_alice)
        pair_a = agent_pair_endpoint(AgentPairRequest(
            pairing_code=gen_a["code"],
            name="Alice-Laptop",
            hostname="alice-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        ), make_req())
        alice_dev_id = pair_a["device_id"]

        # Bob queries Alice's device details -> 403
        with self.assertRaises(HTTPException) as ctx1:
            get_device_details(alice_dev_id, req_bob)
        self.assertEqual(ctx1.exception.status_code, 403)

        # Bob tries to dispatch a task to Alice's device -> 403
        with self.assertRaises(HTTPException) as ctx2:
            create_device_task(
                alice_dev_id,
                DeviceTaskCreateRequest(command=["/usr/bin/echo", "Hacked"]),
                req_bob
            )
        self.assertEqual(ctx2.exception.status_code, 403)

        # Alice's device is NOT in Bob's device list
        bob_devices = list_devices(req_bob)
        self.assertNotIn(alice_dev_id, [d["id"] for d in bob_devices["devices"]])

        # Alice's device IS in Alice's device list
        alice_devices = list_devices(req_alice)
        self.assertIn(alice_dev_id, [d["id"] for d in alice_devices["devices"]])

    def test_08_device_task_lifecycle_permitted_command(self):
        """End-to-end task dispatch: queued by user, fetched by agent, executed, and result recorded."""
        user_req = make_req()
        gen = generate_pairing_code(PairingGenerateRequest(), user_req)
        pair_data = agent_pair_endpoint(AgentPairRequest(
            pairing_code=gen["code"],
            name="Host-Task-Test",
            hostname="task-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        ), user_req)
        dev_id = pair_data["device_id"]
        token = pair_data["token"]

        # 1. User queues a command task
        task = create_device_task(dev_id, DeviceTaskCreateRequest(
            command=["/usr/bin/echo", "Remote Execution Verified"],
            mode="enforce"
        ), user_req)
        task_id = task["id"]
        self.assertEqual(task["status"], "queued")

        # 2. Agent heartbeats and receives the task
        agent_req = make_req(headers={"authorization": f"Bearer {token}"})
        hb = agent_heartbeat_endpoint(AgentHeartbeatRequest(device_id=dev_id), agent_req)
        tasks = hb["tasks"]
        self.assertTrue(any(t["id"] == task_id for t in tasks))

        # 3. Agent executes task locally
        matched_task = next(t for t in tasks if t["id"] == task_id)
        exec_result = execute_agent_task(matched_task, {"permissions": {"allow_execution": True, "share_output": True}})
        self.assertEqual(exec_result["exit_code"], 0)
        self.assertIn("Remote Execution Verified", exec_result["stdout"])

        # 4. Agent reports result back
        report_res = agent_task_result_endpoint(
            task_id,
            AgentTaskResultRequest(status="completed", result=exec_result),
            agent_req
        )
        self.assertEqual(report_res["status"], "received")

        # 5. User inspects recorded task result
        final_task = get_device_task(dev_id, task_id, user_req)
        self.assertEqual(final_task["status"], "completed")
        self.assertEqual(final_task["result"]["exit_code"], 0)

    def test_09_device_task_kernel_sigsys_enforced(self):
        """Enforced seccomp violation on remote device triggers kernel SIGSYS exit."""
        task = {
            "id": "task_sigsys_test",
            "command": ["/usr/bin/uname", "-a"],
            "mode": "enforce"
        }
        # Execute uname under strict echo profile
        import analysis.runner as runner
        orig_find = runner.find_profile_for_target
        runner.find_profile_for_target = lambda name, exp: Path("results/profiles/echo.json")
        try:
            exec_result = execute_agent_task(task, {"permissions": {"allow_execution": True, "share_output": True}})
            # Normalized SIGSYS returncode is either -31 or 159
            self.assertIn(exec_result["exit_code"], {-31, 159})
            self.assertEqual(exec_result["status"], "killed_by_seccomp")
        finally:
            runner.find_profile_for_target = orig_find

    def test_10_device_revocation_stops_agent(self):
        """Revoking a device immediately invalidates credentials and blocks further requests."""
        user_req = make_req()
        gen = generate_pairing_code(PairingGenerateRequest(), user_req)
        pair_data = agent_pair_endpoint(AgentPairRequest(
            pairing_code=gen["code"],
            name="Host-To-Revoke",
            hostname="revoked-box",
            os_info="Linux",
            kernel_version="6.0",
            arch="x86_64"
        ), user_req)
        dev_id = pair_data["device_id"]
        token = pair_data["token"]
        agent_req = make_req(headers={"authorization": f"Bearer {token}"})

        # Confirm agent is active
        hb1 = agent_heartbeat_endpoint(AgentHeartbeatRequest(device_id=dev_id), agent_req)
        self.assertEqual(hb1["status"], "ack")

        # Revoke device from dashboard
        rev_res = revoke_device_endpoint(dev_id, user_req)
        self.assertEqual(rev_res["status"], "revoked")

        # Next heartbeat is rejected with 403 Forbidden
        with self.assertRaises(HTTPException) as ctx:
            agent_heartbeat_endpoint(AgentHeartbeatRequest(device_id=dev_id), agent_req)
        self.assertEqual(ctx.exception.status_code, 403)

        # Task creation is rejected with 400
        with self.assertRaises(HTTPException) as ctx2:
            create_device_task(dev_id, DeviceTaskCreateRequest(command=["/usr/bin/echo", "Denied"]), user_req)
        self.assertEqual(ctx2.exception.status_code, 400)

    def test_11_install_scripts_served(self):
        """Install and agent provisioning scripts are served."""
        inst = get_install_script()
        self.assertIn("PoViShield Remote Linux Agent Installer", inst)
        agent_code = get_agent_script()
        self.assertIn("probe_local_security", agent_code)


if __name__ == "__main__":
    unittest.main()
