// FILE: src/hooks/useSocket.ts — CREATE THIS FILE (new)
// Shared socket.io-client hook used by Layout, ThreatMap, SIEM, and Admin.
// Connects once, re-uses the same underlying socket across all components
// via module-level singleton — avoids creating a new connection per component.

import { useEffect, useRef, MutableRefObject } from "react";
import { io, Socket } from "socket.io-client";
import { API_BASE } from "../config";

// ── Singleton socket — one connection for the whole app ──
let _socket: Socket | null = null;

function getSocket(): Socket {
  if (!_socket) {
    _socket = io(API_BASE, {
      transports: ["websocket", "polling"],
      reconnectionDelay: 2000,
      reconnectionAttempts: 10,
      autoConnect: true,
    });
  }
  return _socket;
}

/** Returns true if the singleton socket currently has an active connection. */
export function isSocketConnected(): boolean {
  return !!_socket?.connected;
}

// ── Hook ──
// Usage:
//   useSocket({
//     threat_detected:   (data) => { ... },
//     ids_alert:         (data) => { ... },
//     siem_alert:        (data) => { ... },
//     honeypot_triggered:(data) => { ... },
//     anomaly_detected:  (data) => { ... },
//     alert_escalated:   (data) => { ... },
//     alert_viewers:     (data) => { ... },
//     connect:           ()     => setConnected(true),
//     disconnect:        ()     => setConnected(false),
//   });

// SocketHandlers type alias (also exported for external use)
export type SocketHandlers = Record<string, (...args: any[]) => void>;

type Handlers = SocketHandlers;

export function useSocket(handlers: Handlers = {}): Socket {
  const handlersRef = useRef<Handlers>(handlers);

  // Keep ref current without re-subscribing on every render
  useEffect(() => {
    handlersRef.current = handlers;
  });

  useEffect(() => {
    const socket = getSocket();

    // Register stable wrappers that delegate to the latest handler ref
    const wrappers: Record<string, (...args: any[]) => void> = {};
    for (const event of Object.keys(handlersRef.current)) {
      wrappers[event] = (...args: any[]) =>
        handlersRef.current[event]?.(...args);
      socket.on(event, wrappers[event]);
    }

    // If the socket is ALREADY connected when this effect runs, the "connect"
    // event has already fired and won't fire again — call the handler now so
    // the caller's state reflects the real connection status immediately.
    if (socket.connected && handlersRef.current["connect"]) {
      handlersRef.current["connect"]();
    }

    return () => {
      for (const [event, fn] of Object.entries(wrappers)) {
        socket.off(event, fn);
      }
    };
  }, []); // mount/unmount only — handler stability handled via ref

  return getSocket();
}

// ── Named emitter helper (optional, used by SIEM alert presence) ──
export function socketEmit(event: string, data?: any): void {
  getSocket().emit(event, data);
}

// ── Ref-based variant ──
// Returns a MutableRefObject<Socket | null> instead of the raw socket,
// matching the pattern used in Scan and other components that prefer refs.
export function useSocketRef(
  handlers: SocketHandlers = {},
): MutableRefObject<Socket | null> {
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    const socket = getSocket();
    socketRef.current = socket;

    Object.entries(handlers).forEach(([event, handler]) => {
      socket.on(event, handler);
    });

    return () => {
      Object.entries(handlers).forEach(([event, handler]) => {
        socket.off(event, handler);
      });
    };
  }, []);

  return socketRef;
}
