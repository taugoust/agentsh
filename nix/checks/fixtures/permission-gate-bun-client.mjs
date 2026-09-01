import { existsSync, lstatSync, statSync } from "node:fs";
import { createConnection } from "node:net";
import { dirname, isAbsolute } from "node:path";

function fail(message) {
  console.error(`permission-gate Bun client: ${message}`);
  process.exit(1);
}

const socketPath = process.env.AGENTSH_PERMISSION_GATE_SOCKET;
if (!socketPath || !isAbsolute(socketPath)) {
  fail("AGENTSH_PERMISSION_GATE_SOCKET is not an absolute path");
}

const rendezvousDir = dirname(socketPath);
let directoryInfo;
let socketInfo;
try {
  directoryInfo = statSync(rendezvousDir);
  socketInfo = lstatSync(socketPath);
} catch (error) {
  fail(`cannot inspect rendezvous: ${error}`);
}
if (!directoryInfo.isDirectory() || (directoryInfo.mode & 0o777) !== 0o700) {
  fail("rendezvous directory is not mode 0700");
}
if (!socketInfo.isSocket()) {
  fail("rendezvous path is not a Unix socket");
}

const connection = createConnection({ path: socketPath });
connection.setEncoding("utf8");
let buffer = "";
let stage = 0;
const timeout = setTimeout(() => fail("protocol timed out"), 5000);

connection.once("connect", () => {
  void (async () => {
    const deadline = Date.now() + 1000;
    while (existsSync(socketPath) || existsSync(rendezvousDir)) {
      if (Date.now() >= deadline) {
        fail("one-shot rendezvous was not unlinked after accept");
      }
      await Bun.sleep(5);
    }
    connection.write(`${JSON.stringify({
      v: 1,
      type: "hello",
      client: "pi-permission-gate",
    })}\n`);
  })().catch((error) => fail(String(error)));
});

connection.on("data", (chunk) => {
  buffer += chunk;
  for (;;) {
    const newline = buffer.indexOf("\n");
    if (newline < 0) {
      return;
    }
    const frame = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);

    let message;
    try {
      message = JSON.parse(frame);
    } catch (error) {
      fail(`invalid JSON response: ${error}`);
    }
    if (stage === 0) {
      if (message.v !== 1 || message.type !== "hello" || message.service !== "agentsh-permission-gate") {
        fail(`unexpected hello response: ${frame}`);
      }
      stage = 1;
      connection.write(`${JSON.stringify({
        v: 1,
        type: "authorize",
        id: "bun-live-check",
        kind: "bash",
        command: "printf bun-live-check",
        cwd: process.cwd(),
      })}\n`);
      continue;
    }
    if (stage === 1) {
      if (message.v !== 1 || message.type !== "decision" || message.id !== "bun-live-check" || message.decision !== "allow") {
        fail(`unexpected decision response: ${frame}`);
      }
      stage = 2;
      clearTimeout(timeout);
      connection.end();
      continue;
    }
    fail(`unexpected extra response: ${frame}`);
  }
});

connection.on("error", (error) => fail(`socket error: ${error}`));
connection.on("close", () => {
  if (stage !== 2) {
    fail("socket closed before authorization completed");
  }
  console.log("permission-gate-bun-live-ok");
});
