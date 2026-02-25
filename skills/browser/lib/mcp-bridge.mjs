#!/usr/bin/env node
// mcp-bridge.mjs -- Lightweight MCP client bridge for Playwright MCP.
//
// Spawns Playwright MCP as a subprocess (stdio transport), initializes
// the MCP session, then exposes a simple HTTP API for the shell skill
// to call browser tools.
//
// Zero npm dependencies -- uses only Node.js built-ins.
//
// HTTP API:
//   POST /call   { "tool": "browser_navigate", "arguments": { "url": "..." } }
//                 -> { "content": [...] }
//   GET  /health  -> { "status": "ok" }
//   POST /stop    -> shuts down bridge + MCP server

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createInterface } from "node:readline";
import { writeFileSync, unlinkSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createConnection } from "node:net";

const STATE_DIR = process.env.AEGIS_STATE_DIR || join(process.env.HOME, ".aegis");
const PID_FILE = join(STATE_DIR, "browser-mcp.pid");
const PORT_FILE = join(STATE_DIR, "browser-mcp.port");
const LOG_FILE = join(STATE_DIR, "browser-mcp.log");

// Ensure state directory exists.
mkdirSync(STATE_DIR, { recursive: true });

// --- MCP stdio client ---

let mcpProcess = null;
let mcpReady = false;
let requestId = 0;
const pendingRequests = new Map(); // id -> { resolve, reject, timer }
let stdoutBuffer = "";

function startMcpServer() {
  const headed = process.env.AEGIS_BROWSER_HEADED === "1";
  const args = ["@playwright/mcp@latest"];
  if (!headed) {
    args.push("--headless");
  }

  mcpProcess = spawn("npx", args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env },
  });

  mcpProcess.on("error", (err) => {
    console.error(`[bridge] MCP process error: ${err.message}`);
    process.exit(1);
  });

  mcpProcess.on("exit", (code) => {
    console.error(`[bridge] MCP process exited with code ${code}`);
    // Reject all pending requests.
    for (const [id, req] of pendingRequests) {
      clearTimeout(req.timer);
      req.reject(new Error(`MCP process exited (code ${code})`));
    }
    pendingRequests.clear();
    mcpProcess = null;
    mcpReady = false;
  });

  // Parse newline-delimited JSON-RPC from stdout.
  mcpProcess.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk.toString();
    let newlineIdx;
    while ((newlineIdx = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, newlineIdx).trim();
      stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        handleMcpMessage(msg);
      } catch (err) {
        console.error(`[bridge] Failed to parse MCP message: ${line}`);
      }
    }
  });

  // Log stderr.
  mcpProcess.stderr.on("data", (chunk) => {
    console.error(`[mcp-stderr] ${chunk.toString().trim()}`);
  });
}

function handleMcpMessage(msg) {
  // JSON-RPC response (has id).
  if (msg.id !== undefined && msg.id !== null) {
    const pending = pendingRequests.get(msg.id);
    if (pending) {
      clearTimeout(pending.timer);
      pendingRequests.delete(msg.id);
      if (msg.error) {
        pending.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      } else {
        pending.resolve(msg.result);
      }
    }
    return;
  }

  // JSON-RPC notification or server request (no id) -- log it.
  if (msg.method) {
    console.error(`[bridge] MCP notification: ${msg.method}`);
  }
}

function sendMcpRequest(method, params) {
  return new Promise((resolve, reject) => {
    if (!mcpProcess || !mcpProcess.stdin.writable) {
      return reject(new Error("MCP process not running"));
    }

    const id = ++requestId;
    const message = JSON.stringify({ jsonrpc: "2.0", id, method, params });

    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error(`MCP request timed out: ${method}`));
    }, 60_000); // 60s timeout per tool call

    pendingRequests.set(id, { resolve, reject, timer });

    mcpProcess.stdin.write(message + "\n", (err) => {
      if (err) {
        clearTimeout(timer);
        pendingRequests.delete(id);
        reject(err);
      }
    });
  });
}

function sendMcpNotification(method, params) {
  if (!mcpProcess || !mcpProcess.stdin.writable) return;
  const message = JSON.stringify({ jsonrpc: "2.0", method, params });
  mcpProcess.stdin.write(message + "\n");
}

async function initializeMcp() {
  const result = await sendMcpRequest("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "aegis-browser", version: "1.0.0" },
  });

  console.error(`[bridge] MCP initialized: ${JSON.stringify(result.serverInfo || {})}`);

  // Send initialized notification.
  sendMcpNotification("notifications/initialized");
  mcpReady = true;
}

// --- HTTP server ---

let httpServer = null;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function jsonResponse(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function handleRequest(req, res) {
  try {
    if (req.method === "GET" && req.url === "/health") {
      return jsonResponse(res, 200, {
        status: mcpReady ? "ok" : "starting",
        pid: process.pid,
      });
    }

    if (req.method === "POST" && req.url === "/call") {
      if (!mcpReady) {
        return jsonResponse(res, 503, { error: "MCP server not ready" });
      }

      const body = JSON.parse(await readBody(req));
      const { tool, arguments: args } = body;

      if (!tool) {
        return jsonResponse(res, 400, { error: "Missing 'tool' field" });
      }

      const result = await sendMcpRequest("tools/call", {
        name: tool,
        arguments: args || {},
      });

      return jsonResponse(res, 200, result);
    }

    if (req.method === "POST" && req.url === "/stop") {
      jsonResponse(res, 200, { status: "stopping" });
      shutdown();
      return;
    }

    jsonResponse(res, 404, { error: "Not found" });
  } catch (err) {
    console.error(`[bridge] Request error: ${err.message}`);
    jsonResponse(res, 500, { error: err.message });
  }
}

function findAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

async function startHttpServer() {
  const port = await findAvailablePort();

  httpServer = createServer(handleRequest);
  httpServer.listen(port, "127.0.0.1", () => {
    console.error(`[bridge] HTTP server listening on 127.0.0.1:${port}`);

    // Write state files.
    writeFileSync(PID_FILE, String(process.pid));
    writeFileSync(PORT_FILE, String(port));
  });
}

// --- Lifecycle ---

function cleanup() {
  try { unlinkSync(PID_FILE); } catch {}
  try { unlinkSync(PORT_FILE); } catch {}
}

function shutdown() {
  console.error("[bridge] Shutting down...");
  cleanup();

  if (mcpProcess) {
    mcpProcess.stdin.end();
    mcpProcess.kill("SIGTERM");
    // Force kill after 3 seconds.
    setTimeout(() => {
      if (mcpProcess) {
        mcpProcess.kill("SIGKILL");
      }
      process.exit(0);
    }, 3000);
  } else {
    process.exit(0);
  }

  if (httpServer) {
    httpServer.close();
  }
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("uncaughtException", (err) => {
  console.error(`[bridge] Uncaught exception: ${err.message}`);
  cleanup();
  process.exit(1);
});

// --- Main ---

async function main() {
  console.error("[bridge] Starting MCP bridge...");

  startMcpServer();

  // Wait for MCP process to be ready (it writes to stdout when ready).
  // Give it up to 120 seconds for first-time Playwright browser download.
  const maxWait = 120_000;
  const start = Date.now();

  while (Date.now() - start < maxWait) {
    try {
      await initializeMcp();
      break;
    } catch (err) {
      if (!mcpProcess) {
        console.error("[bridge] MCP process died during initialization");
        process.exit(1);
      }
      // Retry after a short delay.
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  if (!mcpReady) {
    console.error("[bridge] MCP initialization timed out after 120s");
    cleanup();
    process.exit(1);
  }

  await startHttpServer();
  console.error("[bridge] Ready.");
}

main().catch((err) => {
  console.error(`[bridge] Fatal: ${err.message}`);
  cleanup();
  process.exit(1);
});
