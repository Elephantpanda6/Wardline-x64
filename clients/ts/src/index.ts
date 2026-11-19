import { execFile } from "node:child_process";
import { createConnection } from "node:net";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const DEFAULT_PIPE_NAME =
  process.platform === "win32"
    ? "\\\\.\\pipe\\wardline_guard"
    : "/tmp/wardline_guard.sock";
const MAX_IPC_FRAME_BYTES = 16 * 1024 * 1024;
export const EXIT_APPROVAL_REQUIRED = 3;

export interface GuardResponse {
  status: "ok" | "approval_required" | "denied" | "error";
  payload?: unknown;
  ticket_id?: string;
  action_digest_hex?: string;
  scope_key?: string;
  reason?: string;
  remediation?: string;
  code?: string;
  message?: string;
}

export class WardlineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WardlineError";
  }
}

export class ApprovalRequiredError extends WardlineError {
  readonly ticketId: string;
  readonly actionDigestHex: string;
  readonly scopeKey: string;
  readonly reason: string;

  constructor(
    ticketId: string,
    actionDigestHex: string,
    scopeKey: string,
    reason: string,
  ) {
    super(`approval required (${ticketId}): ${reason}`);
    this.name = "ApprovalRequiredError";
    this.ticketId = ticketId;
    this.actionDigestHex = actionDigestHex;
    this.scopeKey = scopeKey;
    this.reason = reason;
  }
}

export class DeniedError extends WardlineError {
  readonly reason: string;
  readonly remediation?: string;

  constructor(reason: string, remediation?: string) {
    super(remediation ? `denied: ${reason} (${remediation})` : `denied: ${reason}`);
    this.name = "DeniedError";
    this.reason = reason;
    this.remediation = remediation;
  }
}

export function encodeIpcFrame(req: Record<string, unknown>): Buffer {
  const body = Buffer.from(JSON.stringify(req), "utf8");
  if (body.length > MAX_IPC_FRAME_BYTES) {
    throw new Error(`IPC request exceeds max ${MAX_IPC_FRAME_BYTES} bytes`);
  }
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32LE(body.length, 0);
  return Buffer.concat([hdr, body]);
}

export function unwrapCheckedResponse(resp: GuardResponse): GuardResponse {
  if (resp.status === "ok") {
    return resp;
  }
  if (resp.status === "approval_required") {
    throw new ApprovalRequiredError(
      resp.ticket_id ?? "",
      resp.action_digest_hex ?? "",
      resp.scope_key ?? "",
      resp.reason ?? "",
    );
  }
  if (resp.status === "denied") {
    throw new DeniedError(resp.reason ?? "denied", resp.remediation);
  }
  if (resp.status === "error") {
    throw new WardlineError(`${resp.code ?? "error"}: ${resp.message ?? ""}`);
  }
  return resp;
}

export class WardlineClient {
  private readonly wardlineBin: string;
  private readonly pipeName: string;

  constructor(wardlineBin = "wardline", pipeName = DEFAULT_PIPE_NAME) {
    this.wardlineBin = wardlineBin;
    this.pipeName = pipeName;
  }

  private async runJsonCli(cliArgs: string[]): Promise<Record<string, unknown>> {
    try {
      const { stdout } = await execFileAsync(this.wardlineBin, cliArgs);
      return JSON.parse(stdout) as Record<string, unknown>;
    } catch (err: unknown) {
      const stdout = (err as { stdout?: unknown })?.stdout;
      if (typeof stdout === "string" && stdout.trim().length > 0) {
        try {
          return JSON.parse(stdout) as Record<string, unknown>;
        } catch {
        }
      }
      throw err;
    }
  }

  async doctor(): Promise<Record<string, unknown>> {
    return this.runJsonCli(["doctor", "--json"]);
  }

  async policyShow(policy = "schemas/wardline.v1.toml"): Promise<Record<string, unknown>> {
    return this.runJsonCli(["policy", "show", "--policy", policy, "--json"]);
  }

  async runTool(
    executable: string,
    args: string[] = [],
    policy = "schemas/wardline.v1.toml",
    options: { isolation?: string; approvalTicket?: string } = {},
  ): Promise<Record<string, unknown>> {
    const cliArgs = ["run", "--policy", policy, "--json"];
    if (options.isolation) {
      cliArgs.push("--isolation", options.isolation);
    }
    if (options.approvalTicket) {
      cliArgs.push("--approval-ticket", options.approvalTicket);
    }
    cliArgs.push("--", executable, ...args);
    return this.runJsonCli(cliArgs);
  }

  async fetch(
    url: string,
    options: { method?: string; grant?: string; policy?: string } = {},
  ): Promise<Record<string, unknown>> {
    const cliArgs = [
      "fetch",
      "--policy",
      options.policy ?? "schemas/wardline.v1.toml",
      "--method",
      options.method ?? "get",
      "--json",
    ];
    if (options.grant) {
      cliArgs.push("--grant", options.grant);
    }
    cliArgs.push("--", url);
    return this.runJsonCli(cliArgs);
  }

  async checkNet(
    url: string,
    options: { method?: string; grant?: string; policy?: string } = {},
  ): Promise<Record<string, unknown>> {
    const cliArgs = [
      "check-net",
      "--policy",
      options.policy ?? "schemas/wardline.v1.toml",
      "--method",
      options.method ?? "get",
      "--json",
    ];
    if (options.grant) {
      cliArgs.push("--grant", options.grant);
    }
    cliArgs.push("--", url);
    return this.runJsonCli(cliArgs);
  }

  async fsRead(path: string, maxBytes?: number): Promise<GuardResponse> {
    const req: Record<string, unknown> = { type: "broker_file_read", path };
    if (maxBytes !== undefined) {
      req.max_bytes = maxBytes;
    }
    return unwrapCheckedResponse(await this.pipeRequest(req));
  }

  async fsWrite(
    path: string,
    content: string,
    options: { append?: boolean; approvalTicketId?: string } = {},
  ): Promise<GuardResponse> {
    const req: Record<string, unknown> = {
      type: "broker_file_write",
      path,
      content,
      append: options.append ?? false,
    };
    if (options.approvalTicketId) {
      req.approval_ticket_id = options.approvalTicketId;
    }
    return unwrapCheckedResponse(await this.pipeRequest(req));
  }

  async learn(): Promise<GuardResponse> {
    return unwrapCheckedResponse(await this.pipeRequest({ type: "capability_learn" }));
  }

  async auditStats(logPath = "wardline_audit.wlog"): Promise<Record<string, unknown>> {
    return this.runJsonCli(["audit", "stats", "--log", logPath, "--json"]);
  }

  async auditEvents(
    logPath = "wardline_audit.wlog",
    options: { sessionId?: string; limit?: number } = {},
  ): Promise<Record<string, unknown>> {
    const cliArgs = ["audit", "events", "--log", logPath, "--json"];
    if (options.sessionId) {
      cliArgs.push("--session-id", options.sessionId);
    }
    if (options.limit !== undefined) {
      cliArgs.push("--limit", String(options.limit));
    }
    return this.runJsonCli(cliArgs);
  }

  async approveList(store = "wardline_approvals.json"): Promise<Record<string, unknown>> {
    return this.runJsonCli(["approve", "list", "--store", store, "--json"]);
  }

  async approveTicket(
    ticketId: string,
    store = "wardline_approvals.json",
  ): Promise<Record<string, unknown>> {
    return this.runJsonCli(["approve", "approve", "--store", store, "--ticket", ticketId, "--json"]);
  }

  async panic(
    reason: string,
    logPath = "wardline_audit.wlog",
  ): Promise<Record<string, unknown>> {
    return this.runJsonCli(["panic", "--log", logPath, "--reason", reason, "--json"]);
  }

  pipeRequest(req: Record<string, unknown>): Promise<GuardResponse> {
    const frame = encodeIpcFrame(req);

    const sendOnce = (attempt: number): Promise<GuardResponse> =>
      new Promise<GuardResponse>((resolve, reject) => {
        const socket = createConnection(this.pipeName);
        let buf = Buffer.alloc(0);
        let settled = false;

        const fail = (err: Error) => {
          if (!settled) {
            settled = true;
            socket.destroy();
            const code = (err as NodeJS.ErrnoException).code;
            if ((code === "EBUSY" || code === "EAGAIN") && attempt < 139) {
              setTimeout(() => {
                sendOnce(attempt + 1).then(resolve, reject);
              }, 250);
              return;
            }
            reject(err);
          }
        };

        socket.on("error", fail);
        socket.on("connect", () => {
          socket.write(frame);
        });
        socket.on("data", (chunk: Buffer) => {
          if (settled) return;
          buf = Buffer.concat([buf, chunk]);
          if (buf.length >= 4) {
            const respLen = buf.readUInt32LE(0);
            if (respLen === 0 || respLen > MAX_IPC_FRAME_BYTES) {
              fail(new Error(`invalid IPC response length ${respLen}`));
              return;
            }
            if (buf.length >= 4 + respLen) {
              const jsonBytes = buf.subarray(4, 4 + respLen);
              settled = true;
              socket.destroy();
              try {
                resolve(JSON.parse(jsonBytes.toString("utf8")) as GuardResponse);
              } catch (e) {
                reject(e);
              }
            }
          }
        });
        socket.on("end", () => {
          if (!settled) {
            fail(new Error("EOF reading pipe frame"));
          }
        });
      });

    return sendOnce(0);
  }
}
