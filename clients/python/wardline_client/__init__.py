from __future__ import annotations

import errno
import json
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_PIPE_NAME = r"\\.\pipe\wardline_guard"
MAX_IPC_FRAME_BYTES = 16 * 1024 * 1024
ERROR_PIPE_BUSY = 231

def _run_json_cli(cmd: list[str]) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return json.loads(proc.stdout)
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            try:
                return json.loads(exc.stdout)
            except json.JSONDecodeError:
                pass
        raise

@dataclass(frozen=True)
class WardlineClient:

    wardline_bin: str = "wardline"
    pipe_name: str = DEFAULT_PIPE_NAME

    def doctor(self) -> dict[str, Any]:
        return _run_json_cli([self.wardline_bin, "doctor", "--json"])

    def run_tool(
        self,
        executable: str,
        args: list[str] | None = None,
        policy: str = "schemas/wardline.v1.toml",
    ) -> dict[str, Any]:
        cmd = [self.wardline_bin, "run", "--policy", policy, "--json", "--", executable]
        if args:
            cmd.extend(args)
        return _run_json_cli(cmd)

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
        return _run_json_cli(cmd)

    def pipe_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        if len(body) > MAX_IPC_FRAME_BYTES:
            raise ValueError(f"IPC request exceeds max {MAX_IPC_FRAME_BYTES} bytes")
        frame = struct.pack("<I", len(body)) + body

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
