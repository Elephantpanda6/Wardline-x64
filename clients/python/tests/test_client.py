import unittest
from wardline_client import (
    ApprovalRequiredError,
    DeniedError,
    WardlineClient,
    decode_ipc_frame,
    encode_ipc_frame,
    _unwrap_checked_response,
)


class ClientTests(unittest.TestCase):
    def test_frame_roundtrip_and_typed_errors(self) -> None:
        raw = encode_ipc_frame({"type": "health"})
        self.assertEqual(decode_ipc_frame(raw), {"type": "health"})

        with self.assertRaises(ApprovalRequiredError) as app:
            _unwrap_checked_response(
                {
                    "status": "approval_required",
                    "ticket_id": "11111111-1111-1111-1111-111111111111",
                    "action_digest_hex": "abcd",
                    "scope_key": "fs_write:x",
                    "reason": "gate",
                }
            )
        self.assertEqual(app.exception.scope_key, "fs_write:x")

        with self.assertRaises(DeniedError) as den:
            _unwrap_checked_response(
                {
                    "status": "denied",
                    "reason": "LOLBin blocked",
                    "remediation": "Use bounded binary",
                }
            )
        self.assertEqual(den.exception.remediation, "Use bounded binary")

        c = WardlineClient()
        self.assertTrue(bool(c.pipe_name))


if __name__ == "__main__":
    unittest.main()
