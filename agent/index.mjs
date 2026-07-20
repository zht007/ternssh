import http from "node:http";
import net from "node:net";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 18787);
const TOKEN = process.env.AGENT_TOKEN;

if (!TOKEN) {
  throw new Error("AGENT_TOKEN is required");
}

function parseIPv4(host) {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts;
}

function allowedTarget(host) {
  const parts = parseIPv4(host);
  if (!parts) return host.endsWith(".ts.net");
  const [a, b] = parts;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function writeControl(ws, message) {
  if (ws.readyState === 1) ws.send(JSON.stringify(message));
}

const server = http.createServer((request, response) => {
  if (request.url === "/healthz") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  response.writeHead(426, { "content-type": "text/plain" });
  response.end("WebSocket endpoint required\n");
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 32 * 1024 * 1024 });

server.on("upgrade", (request, socket, head) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  const headerToken = request.headers["x-ternssh-agent-token"];
  if (
    requestUrl.pathname !== "/tcp" ||
    typeof headerToken !== "string" ||
    headerToken !== TOKEN
  ) {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request);
  });
});

wss.on("connection", (ws) => {
  let tcp = null;
  let ready = false;
  let closed = false;

  const closeAll = () => {
    if (closed) return;
    closed = true;
    tcp?.destroy();
    if (ws.readyState === 1) ws.close();
  };

  const timer = setTimeout(() => {
    writeControl(ws, { type: "error", message: "Agent handshake timeout" });
    closeAll();
  }, 10000);

  ws.on("message", (data, isBinary) => {
    if (!ready) {
      if (isBinary) {
        writeControl(ws, { type: "error", message: "Invalid Agent handshake" });
        closeAll();
        return;
      }

      let request;
      try {
        request = JSON.parse(data.toString());
      } catch {
        writeControl(ws, { type: "error", message: "Invalid Agent handshake" });
        closeAll();
        return;
      }

      const host = typeof request.host === "string" ? request.host.trim() : "";
      const port = Number(request.port);
      if (request.type !== "open" || !allowedTarget(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
        writeControl(ws, { type: "error", message: "Target is not allowed" });
        closeAll();
        return;
      }

      tcp = net.createConnection({ host, port });
      tcp.once("connect", () => {
        clearTimeout(timer);
        ready = true;
        writeControl(ws, { type: "ready" });
      });
      tcp.on("data", (chunk) => {
        if (ws.readyState === 1) ws.send(chunk, { binary: true });
      });
      tcp.on("error", (error) => {
        if (!ready) writeControl(ws, { type: "error", message: `Target connection failed: ${error.message}` });
        closeAll();
      });
      tcp.on("close", closeAll);
      return;
    }

    if (tcp && !tcp.destroyed) tcp.write(data);
  });

  ws.on("close", () => {
    clearTimeout(timer);
    tcp?.destroy();
  });
  ws.on("error", () => {
    clearTimeout(timer);
    tcp?.destroy();
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ternssh-agent listening on 0.0.0.0:${PORT}`);
});
