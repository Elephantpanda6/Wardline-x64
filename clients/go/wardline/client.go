package wardline

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	MaxIPCFrameBytes     = 16 * 1024 * 1024
	ExitApprovalRequired = 3
)

func DefaultPipeName() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\wardline_guard`
	}
	return "/tmp/wardline_guard.sock"
}

type GuardResponse struct {
	Status          string `json:"status"`
	Payload         any    `json:"payload,omitempty"`
	TicketID        string `json:"ticket_id,omitempty"`
	ActionDigestHex string `json:"action_digest_hex,omitempty"`
	ScopeKey        string `json:"scope_key,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Remediation     string `json:"remediation,omitempty"`
	Code            string `json:"code,omitempty"`
	Message         string `json:"message,omitempty"`
}

type ApprovalRequiredError struct {
	TicketID        string
	ActionDigestHex string
	ScopeKey        string
	Reason          string
}

func (e *ApprovalRequiredError) Error() string {
	return fmt.Sprintf("approval required (%s): %s", e.TicketID, e.Reason)
}

type DeniedError struct {
	Reason      string
	Remediation string
}

func (e *DeniedError) Error() string {
	if e.Remediation != "" {
		return fmt.Sprintf("denied: %s (%s)", e.Reason, e.Remediation)
	}
	return fmt.Sprintf("denied: %s", e.Reason)
}

type Client struct {
	WardlineBin string
	PipeName    string
}

func NewClient(wardlineBin, pipeName string) *Client {
	if wardlineBin == "" {
		wardlineBin = "wardline"
	}
	if pipeName == "" {
		pipeName = DefaultPipeName()
	}
	return &Client{
		WardlineBin: wardlineBin,
		PipeName:    pipeName,
	}
}

func EncodeIPCFrame(payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxIPCFrameBytes {
		return nil, fmt.Errorf("IPC frame %d exceeds limit %d", len(body), MaxIPCFrameBytes)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(body)))
	out := make([]byte, 0, 4+len(body))
	out = append(out, hdr[:]...)
	out = append(out, body...)
	return out, nil
}

func DecodeIPCFrame(r io.Reader) (*GuardResponse, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > MaxIPCFrameBytes {
		return nil, fmt.Errorf("invalid IPC frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var resp GuardResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func CheckResponse(resp *GuardResponse) (*GuardResponse, error) {
	if resp == nil {
		return nil, errors.New("nil GuardResponse")
	}
	switch resp.Status {
	case "ok":
		return resp, nil
	case "approval_required":
		return nil, &ApprovalRequiredError{
			TicketID:        resp.TicketID,
			ActionDigestHex: resp.ActionDigestHex,
			ScopeKey:        resp.ScopeKey,
			Reason:          resp.Reason,
		}
	case "denied":
		return nil, &DeniedError{
			Reason:      resp.Reason,
			Remediation: resp.Remediation,
		}
	case "error":
		return nil, fmt.Errorf("%s: %s", resp.Code, resp.Message)
	default:
		return resp, nil
	}
}

func (c *Client) PipeRequest(req any) (*GuardResponse, error) {
	frame, err := EncodeIPCFrame(req)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(c.PipeName, `\\`) {
		conn, err := net.Dial("unix", c.PipeName)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if _, err := conn.Write(frame); err != nil {
			return nil, err
		}
		return DecodeIPCFrame(conn)
	}
	fh, err := os.OpenFile(c.PipeName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if _, err := fh.Write(frame); err != nil {
		return nil, err
	}
	return DecodeIPCFrame(fh)
}

func (c *Client) RunCLIJSON(args ...string) (map[string]any, error) {
	cmd := exec.Command(c.WardlineBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.Len() > 0 {
		var parsed map[string]any
		if jErr := json.Unmarshal(stdout.Bytes(), &parsed); jErr == nil {
			return parsed, err
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wardline CLI failed (%w): %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil, errors.New("empty JSON output from wardline")
}

func (c *Client) Doctor() (map[string]any, error) {
	return c.RunCLIJSON("doctor", "--json")
}

func (c *Client) AuditStats(logPath string) (map[string]any, error) {
	return c.RunCLIJSON("audit", "stats", "--log", logPath, "--json")
}
