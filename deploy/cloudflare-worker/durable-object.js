// Cloudflare Worker Durable Object for WebSocket persistence
// This object maintains WebSocket connections even during hibernation

export class WebSocketDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.ws = null;
    this.socket = null;
    this.writer = null;
    this.opened = false;
    this.connectionStatus = "initializing";
    this.directFallbackAttempted = false;
    
    // Restore state if rehydrated from hibernation
    const stored = await this.state.storage.get("connection_state");
    if (stored) {
      this.connectionStatus = stored.status || "restored";
      this.directFallbackAttempted = stored.fallbackAttempted || false;
    }
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected websocket', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair());
    
    // Accept the WebSocket connection and enable Hibernation
    this.ctx.acceptWebSocket(server);
    
    // Store client reference
    this.ws = server;
    this.ws.binaryType = "arraybuffer";
    
    // Persist connection metadata
    await this.state.storage.put("connection_metadata", {
      connectedAt: Date.now(),
      clientId: request.headers.get('x-client-id') || 'unknown'
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async webSocketMessage(ws, message) {
    try {
      // Reset idle timer on activity
      await this.state.storage.put("last_activity", Date.now());
      
      if (!this.opened) {
        // First message should be the hello/control message
        const hello = this.parseJsonControl(message);
        
        if (!this.authorizedTcpHello(hello)) {
          ws.send(JSON.stringify({ ok: false, e: "unauthorized" }));
          ws.close(1008, "unauthorized");
          return;
        }

        const host = String(hello.host || "");
        const port = parseInt(hello.port, 10);
        
        if (!this.validTcpTarget(host, port)) {
          ws.send(JSON.stringify({ ok: false, e: "bad tcp target" }));
          ws.close(1008, "bad tcp target");
          return;
        }

        // Update status
        this.connectionStatus = `connecting_to_${host}:${port}`;
        await this.updateConnectionState();
        ws.send(JSON.stringify({ op: "status", status: this.connectionStatus }));

        try {
          // Connect to TCP target
          const { connect } = await import("cloudflare:sockets");
          this.socket = connect({ hostname: host, port }, { allowHalfOpen: true });
          
          // Wait for connection with timeout
          await this.waitForSocketOpened(this.socket, 10000);
          this.writer = this.socket.writable.getWriter();
          this.opened = true;
          
          // Update status on success
          this.connectionStatus = "connected";
          await this.updateConnectionState();
          ws.send(JSON.stringify({ ok: true, status: "connected" }));
          
          // Start piping TCP data to WebSocket
          this.pipeTcpToWebSocket();
          
        } catch (connErr) {
          // Connection failed
          this.connectionStatus = `connection_failed: ${connErr.message}`;
          await this.updateConnectionState();
          
          // Send error with fallback suggestion
          ws.send(JSON.stringify({ 
            ok: false, 
            e: `TCP connection failed: ${connErr.message}`,
            fallback_suggestion: true,
            status: this.connectionStatus
          }));
          
          throw connErr;
        }
        return;
      }

      // Handle subsequent messages
      if (typeof message === "string") {
        const ctrl = this.parseJsonControl(message);
        if (ctrl.op === "close") {
          await this.closeTcpWriter();
          ws.close(1000, "client closed");
        }
        return;
      }

      // Forward binary data to TCP socket
      const chunk = await this.websocketDataToUint8Array(message);
      await this.writer.write(chunk);
      
    } catch (err) {
      try {
        ws.send(JSON.stringify({ op: "error", e: String(err.message || err) }));
        ws.close(1011, "tcp write failed");
      } catch (_) {
        // Socket already closed
      }
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    console.log(`WebSocket closed: ${code} ${reason}`);
    await this.closeTcpWriter();
    try {
      if (this.socket) await this.socket.close();
    } catch (_) {
      // Already closed
    }
    
    // Clean up storage
    await this.state.storage.delete("connection_state");
    await this.state.storage.delete("connection_metadata");
  }

  async webSocketError(ws, error) {
    console.error("WebSocket error:", error);
    this.connectionStatus = "error";
    await this.updateConnectionState();
    ws.close(1011, "WebSocket error");
  }

  // Helper methods
  parseJsonControl(data) {
    if (typeof data !== "string") return {};
    try {
      return JSON.parse(data);
    } catch (_) {
      return {};
    }
  }

  authorizedTcpHello(hello) {
    const expected = this.env.WORKER_WS_AUTH_KEY || this.env.UPSTREAM_AUTH_KEY || "";
    return !!expected && hello && hello.v === 1 &&
      hello.op === "connect" && hello.k === expected;
  }

  validTcpTarget(host, port) {
    const BLOCKED_PORTS = new Set([
      22, 23, 25, 110, 143, 445, 465, 587, 993, 995,
      1433, 1521, 3306, 3389, 5432, 5900, 6379,
      9200, 9300, 11211, 27017, 27018,
    ]);
    
    if (!host || host.length > 253) return false;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
    if (BLOCKED_PORTS.has(port)) return false;
    
    const lowered = host.toLowerCase();
    const WORKER_URL = this.env.WORKER_URL || "YOUR_WORKER_HOSTNAME.workers.dev";
    
    if (lowered === WORKER_URL || lowered.endsWith("." + WORKER_URL)) return false;
    if (lowered === "localhost" || lowered.endsWith(".local") || lowered.endsWith(".internal")) return false;
    if (lowered.startsWith("10.") || lowered.startsWith("192.168.") ||
        lowered.startsWith("127.") || lowered.startsWith("169.254.") || lowered === "0.0.0.0") return false;
    if (lowered.startsWith("172.")) {
      const second = parseInt(lowered.split(".")[1], 10);
      if (second >= 16 && second <= 31) return false;
    }
    if (lowered === "::1" || lowered.startsWith("fc") || lowered.startsWith("fd") || lowered.startsWith("fe80")) return false;
    
    return true;
  }

  async waitForSocketOpened(socket, timeoutMs) {
    let timer;
    try {
      await Promise.race([
        socket.opened,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("TCP connect timeout")), timeoutMs);
        })
      ]);
    } catch (err) {
      try {
        await socket.close();
      } catch (_) {
        // Already closed
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async pipeTcpToWebSocket() {
    if (!this.socket || !this.ws) return;
    
    const reader = this.socket.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          await this.state.storage.put("last_activity", Date.now());
          this.ws.send(value);
        }
      }
      this.ws.send(JSON.stringify({ op: "close" }));
      this.ws.close(1000, "target closed");
    } catch (err) {
      try {
        this.ws.send(JSON.stringify({ op: "error", e: String(err.message || err) }));
        this.ws.close(1011, "tcp read failed");
      } catch (_) {
        // Socket already closed
      }
    } finally {
      try {
        reader.releaseLock();
      } catch (_) {
        // Already released
      }
    }
  }

  async closeTcpWriter() {
    if (!this.writer) return;
    try {
      await this.writer.close();
      this.writer.releaseLock();
    } catch (_) {
      try {
        this.writer.releaseLock();
      } catch (_) {
        // Already released
      }
    }
  }

  async websocketDataToUint8Array(data) {
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (data instanceof Uint8Array) {
      return data;
    }
    if (data && typeof data.arrayBuffer === "function") {
      return new Uint8Array(await data.arrayBuffer());
    }
    return new TextEncoder().encode(String(data || ""));
  }

  async updateConnectionState() {
    await this.state.storage.put("connection_state", {
      status: this.connectionStatus,
      fallbackAttempted: this.directFallbackAttempted,
      updatedAt: Date.now()
    });
  }
}
