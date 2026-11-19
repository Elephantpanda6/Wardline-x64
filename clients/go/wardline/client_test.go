package wardline

import (
	"bytes"
	"errors"
	"testing"
)

func TestIPCFrameAndCheckedResponse(t *testing.T) {
	frame, err := EncodeIPCFrame(map[string]string{"type": "health"})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if len(frame) <= 4 {
		t.Fatalf("frame unexpectedly short: %d", len(frame))
	}

	okBytes, err := EncodeIPCFrame(&GuardResponse{Status: "ok"})
	if err != nil {
		t.Fatalf("encode ok response failed: %v", err)
	}
	decoded, err := DecodeIPCFrame(bytes.NewReader(okBytes))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if _, err := CheckResponse(decoded); err != nil {
		t.Fatalf("unexpected error checking ok response: %v", err)
	}

	var appErr *ApprovalRequiredError
	_, err = CheckResponse(&GuardResponse{
		Status:   "approval_required",
		TicketID: "t-1",
		ScopeKey: "exec:cargo",
		Reason:   "human confirm",
	})
	if !errors.As(err, &appErr) {
		t.Fatalf("expected ApprovalRequiredError, got %v", err)
	}
}
