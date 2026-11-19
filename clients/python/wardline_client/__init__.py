from __future__ import annotations

import errno
import json
import os
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_PIPE_NAME = (
    r"\\.\pipe\wardline_guard" if os.name == "nt" else "/tmp/wardline_guard.sock"
)
MAX_IPC_FRAME_BYTES = 16 * 1024 * 1024
ERROR_PIPE_BUSY = 231
EXIT_APPROVAL_REQUIRED = 3


class WardlineError(RuntimeError):
    """Base error raised by WardlineClient checked helpers."""


class ApprovalRequiredError(WardlineError):
    def __init__(
        self,
        ticket_id: str,
        action_digest_hex: str,
        scope_key: str,
        reason: str,
    ) -> None:
        super().__init__(f"approval required ({ticket_id}): {reason}")
        self.ticket_id = ticket_id
        self.action_digest_hex = action_digest_hex
        self.scope_key = scope_key
        self.reason = reason


class DeniedError(WardlineError):
    def __init__(self, reason: str, remediation: str | None = None) -> None:
        msg = f"denied: {reason}" if not remediation else f"denied: {reason} ({remediation})"
        super().__init__(msg)
        self.reason = reason
        self.remediation = remediation


def _run_json_cli(cmd: list[str], allow_exit_codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode in allow_exit_codes or (proc.stdout and proc.stdout.strip().startswith("{")):
        try:
            payload = json.loads(proc.stdout)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr
        )
    return json.loads(proc.stdout)


def encode_ipc_frame(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    if len(body) > MAX_IPC_FRAME_BYTES:
        raise ValueError(f"IPC request exceeds max {MAX_IPC_FRAME_BYTES} bytes")
    return struct.pack("<I", len(body)) + body


def decode_ipc_frame(buf: bytes) -> dict[str, Any]:
    if len(buf) < 4:
        raise ValueError("truncated IPC frame header")
    length = struct.unpack("<I", buf[:4])[0]
    if length == 0 or length > MAX_IPC_FRAME_BYTES or len(buf) < 4 + length:
        raise ValueError(f"invalid IPC response length {length}")
    return json.loads(buf[4 : 4 + length].decode("utf-8"))


@dataclass(frozen=True)
class WardlineClient:
    wardline_bin: str = "wardline"
    pipe_name: str = DEFAULT_PIPE_NAME

    def doctor(self) -> dict[str, Any]:
        return _run_json_cli([self.wardline_bin, "doctor", "--json"])

    def policy_show(self, policy: str = "schemas/wardline.v1.toml") -> dict[str, Any]:
        return _run_json_cli([self.wardline_bin, "policy", "show", "--policy", policy, "--json"])

    def run_tool(
        self,
        executable: str,
        args: list[str] | None = None,
        policy: str = "schemas/wardline.v1.toml",
        isolation: str | None = None,
        approval_ticket: str | None = None,
    ) -> dict[str, Any]:
        cmd = [self.wardline_bin, "run", "--policy", policy, "--json"]
        if isolation:
            cmd.extend(["--isolation", isolation])
        if approval_ticket:
            cmd.extend(["--approval-ticket", approval_ticket])
        cmd.extend(["--", executable])
        if args:
            cmd.extend(args)
        return _run_json_cli(cmd, allow_exit_codes=(0, EXIT_APPROVAL_REQUIRED))

    def run_tool_checked(
        self,
        executable: str,
        args: list[str] | None = None,
        policy: str = "schemas/wardline.v1.toml",
        isolation: str | None = None,
        approval_ticket: str | None = None,
    ) -> dict[str, Any]:
        resp = self.run_tool(
            executable,
            args=args,
            policy=policy,
            isolation=isolation,
            approval_ticket=approval_ticket,
        )
        return _unwrap_checked_response(resp)

    def fetch(
        self,
        url: str,
        method: str = "get",
        grant: str | None = None,
        policy: str = "schemas/wardline.v1.toml",
    ) -> dict[str, Any]:
        cmd = [self.wardline_bin, "fetch", "--policy", policy, "--method", method, "--json"]
        if grant:
            cmd.extend(["--grant", grant])
        cmd.extend(["--", url])
        return _run_json_cli(cmd, allow_exit_codes=(0, EXIT_APPROVAL_REQUIRED))

    def check_net(
        self,
        url: str,
        method: str = "get",
        grant: str | None = None,
        policy: str = "schemas/wardline.v1.toml",
    ) -> dict[str, Any]:
        cmd = [self.wardline_bin, "check-net", "--policy", policy, "--method", method, "--json"]
        if grant:
            cmd.extend(["--grant", grant])
        cmd.extend(["--", url])
        return _run_json_cli(cmd)

    def fs_read(self, path: str, max_bytes: int | None = None) -> dict[str, Any]:
        req: dict[str, Any] = {"type": "broker_file_read", "path": path}
        if max_bytes is not None:
            req["max_bytes"] = max_bytes
        return _unwrap_checked_response(self.pipe_request(req))

    def fs_write(
        self,
        path: str,
        content: str,
        append: bool = False,
        approval_ticket_id: str | None = None,
    ) -> dict[str, Any]:
        req: dict[str, Any] = {
            "type": "broker_file_write",
            "path": path,
            "content": content,
            "append": append,
        }
        if approval_ticket_id:
            req["approval_ticket_id"] = approval_ticket_id
        return _unwrap_checked_response(self.pipe_request(req))

    def learn(self) -> dict[str, Any]:
        return _unwrap_checked_response(self.pipe_request({"type": "capability_learn"}))

    def audit_stats(self, log_path: str = "wardline_audit.wlog") -> dict[str, Any]:
        return _run_json_cli([self.wardline_bin, "audit", "stats", "--log", log_path, "--json"])

    def audit_events(
        self,
        log_path: str = "wardline_audit.wlog",
        session_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        cmd = [self.wardline_bin, "audit", "events", "--log", log_path, "--json"]
        if session_id:
            cmd.extend(["--session-id", session_id])
        if limit is not None:
            cmd.extend(["--limit", str(limit)])
        return _run_json_cli(cmd)

    def approve_list(self, store: str = "wardline_approvals.json") -> dict[str, Any]:
        return _run_json_cli([self.wardline_bin, "approve", "list", "--store", store, "--json"])

    def approve_ticket(self, ticket_id: str, store: str = "wardline_approvals.json") -> dict[str, Any]:
        return _run_json_cli(
            [self.wardline_bin, "approve", "approve", "--store", store, "--ticket", ticket_id, "--json"]
        )

    def panic(
        self,
        reason: str,
        log_path: str = "wardline_audit.wlog",
    ) -> dict[str, Any]:
        return _run_json_cli(
            [self.wardline_bin, "panic", "--log", log_path, "--reason", reason, "--json"]
        )

    def pipe_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        frame = encode_ipc_frame(payload)

        if os.name != "nt" and not self.pipe_name.startswith(r"\\"):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.connect(self.pipe_name)
                sock.sendall(frame)
                hdr = _recv_exact_socket(sock, 4)
                resp_len = struct.unpack("<I", hdr)[0]
                if resp_len == 0 or resp_len > MAX_IPC_FRAME_BYTES:
                    raise ValueError(f"invalid IPC response length {resp_len}")
                resp_bytes = _recv_exact_socket(sock, resp_len)
                return json.loads(resp_bytes.decode("utf-8"))

        def _read_exact(pipe: Any, n: int) -> bytes:
            chunks = bytearray()
            while len(chunks) < n:
                chunk = pipe.read(n - len(chunks))
                if not chunk:
                    raise EOFError("short read on Wardline pipe frame")
                chunks.extend(chunk)
            return bytes(chunks)

        pipe_fh = None
        for attempt in range(140):
            try:
                pipe_fh = open(self.pipe_name, "r+b", buffering=0)
                break
            except OSError as exc:
                is_busy = getattr(exc, "winerror", None) == ERROR_PIPE_BUSY or exc.errno == errno.EBUSY
                if is_busy and attempt < 139:
                    time.sleep(0.25)
                    continue
                raise

        assert pipe_fh is not None
        with pipe_fh as pipe:
            view = memoryview(frame)
            written = 0
            while written < len(frame):
                n = pipe.write(view[written:])
                if not n:
                    raise OSError("short write on Wardline pipe frame")
                written += n
            raw_len = _read_exact(pipe, 4)
            resp_len = struct.unpack("<I", raw_len)[0]
            if resp_len == 0 or resp_len > MAX_IPC_FRAME_BYTES:
                raise ValueError(f"invalid IPC response length {resp_len}")
            resp_bytes = _read_exact(pipe, resp_len)
        return json.loads(resp_bytes.decode("utf-8"))


def _unwrap_checked_response(resp: dict[str, Any]) -> dict[str, Any]:
    status = resp.get("status")
    if status == "ok":
        return resp
    if status == "approval_required":
        raise ApprovalRequiredError(
            ticket_id=str(resp.get("ticket_id", "")),
            action_digest_hex=str(resp.get("action_digest_hex", "")),
            scope_key=str(resp.get("scope_key", "")),
            reason=str(resp.get("reason", "")),
        )
    if status == "denied":
        raise DeniedError(
            reason=str(resp.get("reason", "denied")),
            remediation=resp.get("remediation"),
        )
    if status == "error":
        raise WardlineError(f"{resp.get('code', 'error')}: {resp.get('message', '')}")
    return resp


def _recv_exact_socket(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise EOFError("short read on Wardline Unix socket frame")
        chunks.extend(chunk)
    return bytes(chunks)
