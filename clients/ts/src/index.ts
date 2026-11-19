import { execFile } from "node:child_process";
import { createConnection } from "node:net";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const DEFAULT_PIPE_NAME =
  process.platform === "win32"
    ? "\\\\.\\pipe\\wardline_guard"
    : "/tmp/wardline_guard.sock";
const MAX_IPC_FRAME_BYTES = 16 * 1024 * 1024;

export interface GuardResponse {
  status: "ok" | "approval_required" | "denied" | "error";
  payload?: unknown;
  ticket_id?: string;
  action_digest_hex?: string;
  scope_key?: string;
  reason?: string;
  code?: string;
  message?: string;
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

  async runTool(
    executable: string,
    args: string[] = [],
    policy = "schemas/wardline.v1.toml",
  ): Promise<Record<string, unknown>> {
    const cliArgs = ["run", "--policy", policy, "--json", "--", executable, ...args];
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

  pipeRequest(req: Record<string, unknown>): Promise<GuardResponse> {
    const body = Buffer.from(JSON.stringify(req), "utf8");
    if (body.length > MAX_IPC_FRAME_BYTES) {
      return Promise.reject(
        new Error(`IPC request exceeds max ${MAX_IPC_FRAME_BYTES} bytes`),
      );
    }
    const hdr = Buffer.alloc(4);
    hdr.writeUInt32LE(body.length, 0);
    const frame = Buffer.concat([hdr, body]);

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
