const DOH_URL = "https://1.1.1.1/dns-query";

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
}

function stripBrackets(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function isIPv4(host: string): boolean {
  return IPV4_RE.test(host);
}

function isIPv6(host: string): boolean {
  if (!host.includes(":")) return false;
  return /^[0-9a-fA-F:.]+$/.test(host);
}

function ipv4Parts(host: string): number[] | null {
  if (!isIPv4(host)) return null;
  return host.split(".").map((part) => Number(part));
}

function isAgentRoutableIPv4(host: string): boolean {
  const parts = ipv4Parts(host);
  if (!parts) return false;
  const [a, b] = parts;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function shouldUseAgent(host: string): boolean {
  const normalized = stripBrackets(host);
  return isAgentRoutableIPv4(normalized) || normalized.endsWith(".ts.net");
}

interface TunnelSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<void>;
  close(): void;
}

export function isIpAddress(host: string): boolean {
  const normalized = stripBrackets(host);
  return isIPv4(normalized) || isIPv6(normalized);
}

function isValidDomainName(host: string): boolean {
  if (
    host.length > 253 ||
    !/^[a-zA-Z0-9.-]+$/.test(host) ||
    host.startsWith(".") ||
    host.endsWith(".") ||
    host.includes("..")
  ) {
    return false;
  }

  for (const label of host.split(".")) {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }

  return true;
}

export function isValidServerHost(host: string): boolean {
  const normalized = stripBrackets(host.trim());
  if (!normalized) return false;
  return isIpAddress(normalized) || isValidDomainName(normalized);
}

function formatConnectHostname(address: string): string {
  return address.includes(":") ? `[${address}]` : address;
}

async function queryDoh(name: string, type: "A" | "AAAA"): Promise<string | null> {
  const url = new URL(DOH_URL);
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);

  const response = await fetch(url.toString(), {
    headers: { Accept: "application/dns-json" },
  });
  if (!response.ok) {
    throw new Error(`DNS 查询失败 (${response.status})`);
  }

  const body = (await response.json()) as DohResponse;
  if (body.Status !== 0 || !body.Answer?.length) {
    return null;
  }

  const typeCode = type === "A" ? 1 : 28;
  const record = body.Answer.find((answer) => answer.type === typeCode);
  return record?.data ?? null;
}

export async function resolveHostAddress(host: string): Promise<string> {
  const normalized = stripBrackets(host);
  if (!normalized) {
    throw new Error("主机名为空");
  }

  if (isIpAddress(normalized)) {
    return normalized;
  }

  if (!isValidDomainName(normalized)) {
    throw new Error("无效的主机名");
  }

  const ipv4 = await queryDoh(normalized, "A");
  if (ipv4) return ipv4;

  const ipv6 = await queryDoh(normalized, "AAAA");
  if (ipv6) return ipv6;

  throw new Error(`无法解析域名: ${normalized}`);
}

async function connectViaAgent(
  env: Pick<Env, "SSH_AGENT_URL" | "SSH_AGENT_TOKEN">,
  host: string,
  port: number,
): Promise<TunnelSocket> {
  const agentUrl = new URL(env.SSH_AGENT_URL!);
  const response = await fetch(agentUrl, {
    headers: {
      Upgrade: "websocket",
      "X-TernSSH-Agent-Token": env.SSH_AGENT_TOKEN!,
    },
  });
  const ws = response.webSocket;
  if (!ws) {
    throw new Error(`SSH Agent WebSocket 握手失败 (${response.status})`);
  }

  ws.accept({ allowHalfOpen: true });

  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  let settled = false;
  const buffered: Uint8Array[] = [];
  let resolveOpened!: () => void;
  let rejectOpened!: (error: Error) => void;
  const opened = new Promise<void>((resolve, reject) => {
    resolveOpened = resolve;
    rejectOpened = reject;
  });

  const fail = (error: Error) => {
    if (!settled) {
      settled = true;
      rejectOpened(error);
    }
  };

  const readable = new ReadableStream<Uint8Array>({
    start(streamController) {
      controller = streamController;
      for (const chunk of buffered.splice(0)) {
        streamController.enqueue(chunk);
      }
    },
    cancel() {
      try {
        ws.close();
      } catch {
        // ignore close errors
      }
    },
  });

  ws.addEventListener("message", async (event) => {
    if (typeof event.data === "string") {
      try {
        const message = JSON.parse(event.data) as {
          type?: string;
          message?: string;
        };
        if (message.type === "ready") {
          if (!settled) {
            settled = true;
            resolveOpened();
          }
          return;
        }
        if (message.type === "error") {
          fail(new Error(message.message || "SSH Agent 连接失败"));
        }
      } catch {
        fail(new Error("SSH Agent 返回了无效控制消息"));
      }
      return;
    }

    const data =
      event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : event.data instanceof Blob
          ? new Uint8Array(await event.data.arrayBuffer())
          : new Uint8Array(event.data as ArrayBuffer);
    if (controller) controller.enqueue(data);
    else buffered.push(data);
  });

  ws.addEventListener("error", () => fail(new Error("SSH Agent WebSocket 错误")));
  ws.addEventListener("close", () => {
    if (!settled) fail(new Error("SSH Agent 连接已关闭"));
    try {
      controller?.close();
    } catch {
      // ignore close errors
    }
  });

  ws.send(JSON.stringify({ type: "open", host, port }));

  return {
    readable,
    writable: new WritableStream<Uint8Array>({
      write(data) {
        if (ws.readyState !== WebSocket.OPEN) {
          throw new Error("SSH Agent 连接未打开");
        }
        ws.send(data);
      },
      close() {
        try {
          ws.close();
        } catch {
          // ignore close errors
        }
      },
      abort() {
        try {
          ws.close();
        } catch {
          // ignore close errors
        }
      },
    }),
    opened,
    close() {
      try {
        ws.close();
      } catch {
        // ignore close errors
      }
    },
  };
}

export async function connectToHost(
  env: Pick<Env, "SSH_AGENT_URL" | "SSH_AGENT_TOKEN">,
  host: string,
  port: number,
) {
  if (env.SSH_AGENT_URL && env.SSH_AGENT_TOKEN && shouldUseAgent(host)) {
    const socket = await connectViaAgent(env, host, port);
    await socket.opened;
    return socket;
  }

  const { connect } = await import("cloudflare:sockets");
  const address = await resolveHostAddress(host);
  const socket = connect({
    hostname: formatConnectHostname(address),
    port,
  });
  await socket.opened;
  return socket;
}
