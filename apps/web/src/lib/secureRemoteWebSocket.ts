// FILE: secureRemoteWebSocket.ts
// Purpose: Browser WebSocket adapter that performs the secure remote handshake and frame encryption.
// Layer: Web transport utility

import {
  createClientAuth,
  createClientHello,
  decryptSecureFrame,
  deriveClientSession,
  encryptSecureFrame,
  parseSecureControlMessage,
  serializeSecureControlMessage,
  type SecureFrame,
  type SecureRemoteIdentity,
  type SecureRemotePairingServerIdentity,
  type SecureServerHello,
  type SecureTransportSession,
} from "@t3tools/shared/secureRemote";

type NativeWebSocketConstructor = typeof globalThis.WebSocket;
type Listener = EventListenerOrEventListenerObject;

interface ListenerEntry {
  readonly listener: Listener;
  readonly once: boolean;
}

function isListenerObject(listener: Listener): listener is EventListenerObject {
  return typeof listener === "object" && listener !== null && "handleEvent" in listener;
}

function makeEvent(type: string): Event {
  return typeof Event === "function" ? new Event(type) : ({ type } as Event);
}

function makeMessageEvent(data: Uint8Array): MessageEvent {
  if (typeof MessageEvent === "function") {
    return new MessageEvent("message", { data });
  }
  return { type: "message", data } as MessageEvent;
}

function makeCloseEvent(code: number, reason: string): CloseEvent {
  if (typeof CloseEvent === "function") {
    return new CloseEvent("close", { code, reason });
  }
  return { type: "close", code, reason } as CloseEvent;
}

async function readIncomingText(data: unknown): Promise<string> {
  if (typeof data === "string") return data;
  if (data instanceof Uint8Array) return new TextDecoder().decode(data);
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(data));
  if (typeof Blob === "function" && data instanceof Blob) {
    return data.text();
  }
  throw new Error("Unsupported secure remote WebSocket message type.");
}

export interface SecureRemoteWebSocketOptions {
  readonly nativeWebSocket: NativeWebSocketConstructor;
  readonly clientIdentity: SecureRemoteIdentity;
  readonly trustedServer: SecureRemotePairingServerIdentity;
}

export class SecureRemoteWebSocket {
  readonly CONNECTING = WebSocket.CONNECTING;
  readonly OPEN = WebSocket.OPEN;
  readonly CLOSING = WebSocket.CLOSING;
  readonly CLOSED = WebSocket.CLOSED;

  readonly url: string;
  readonly protocol = "";
  readonly extensions = "";
  binaryType: BinaryType = "arraybuffer";
  bufferedAmount = 0;
  readyState = WebSocket.CONNECTING;

  onopen: ((this: WebSocket, ev: Event) => unknown) | null = null;
  onmessage: ((this: WebSocket, ev: MessageEvent) => unknown) | null = null;
  onerror: ((this: WebSocket, ev: Event) => unknown) | null = null;
  onclose: ((this: WebSocket, ev: CloseEvent) => unknown) | null = null;

  private readonly nativeSocket: WebSocket;
  private readonly listeners = new Map<string, ListenerEntry[]>();
  private readonly pending: ReturnType<typeof createClientHello>;
  private session: SecureTransportSession | null = null;
  private closed = false;

  constructor(
    url: string | URL,
    protocols: string | string[] | undefined,
    private readonly options: SecureRemoteWebSocketOptions,
  ) {
    this.url = url.toString();
    this.pending = createClientHello({
      clientIdentity: options.clientIdentity,
      expectedServer: options.trustedServer,
    });
    this.nativeSocket = new options.nativeWebSocket(this.url, protocols);
    this.nativeSocket.binaryType = "arraybuffer";
    this.nativeSocket.addEventListener("open", this.handleNativeOpen);
    this.nativeSocket.addEventListener("message", this.handleNativeMessage);
    this.nativeSocket.addEventListener("error", this.handleNativeError);
    this.nativeSocket.addEventListener("close", this.handleNativeClose);
  }

  addEventListener(type: string, listener: Listener, options?: AddEventListenerOptions): void {
    const entries = this.listeners.get(type) ?? [];
    entries.push({ listener, once: Boolean(options?.once) });
    this.listeners.set(type, entries);
  }

  removeEventListener(type: string, listener: Listener): void {
    const entries = this.listeners.get(type);
    if (!entries) return;
    this.listeners.set(
      type,
      entries.filter((entry) => entry.listener !== listener),
    );
  }

  dispatchEvent(event: Event): boolean {
    this.emit(event.type, event);
    return true;
  }

  send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void {
    if (!this.session || this.readyState !== WebSocket.OPEN) {
      throw new Error("Secure remote WebSocket is not open.");
    }
    if (typeof Blob === "function" && data instanceof Blob) {
      void data.arrayBuffer().then((buffer) => this.sendBytes(new Uint8Array(buffer)));
      return;
    }
    if (typeof data === "string") {
      this.sendBytes(new TextEncoder().encode(data));
      return;
    }
    if (ArrayBuffer.isView(data)) {
      this.sendBytes(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      return;
    }
    this.sendBytes(new Uint8Array(data));
  }

  close(code = 1000, reason = ""): void {
    if (this.closed) return;
    this.readyState = WebSocket.CLOSING;
    this.nativeSocket.close(code, reason);
  }

  private readonly handleNativeOpen = () => {
    this.nativeSocket.send(serializeSecureControlMessage(this.pending.hello));
  };

  private readonly handleNativeMessage = (event: MessageEvent) => {
    void this.consumeNativeMessage(event.data).catch((error) => this.failHandshake(error));
  };

  private readonly handleNativeError = (event: Event) => {
    this.emit("error", event);
  };

  private readonly handleNativeClose = (event: CloseEvent) => {
    this.closed = true;
    this.readyState = WebSocket.CLOSED;
    this.emit("close", makeCloseEvent(event.code, event.reason));
  };

  private async consumeNativeMessage(data: unknown): Promise<void> {
    const message = parseSecureControlMessage(await readIncomingText(data));
    if (!this.session) {
      const serverHello = message as SecureServerHello;
      const session = deriveClientSession({
        clientHello: this.pending.hello,
        serverHello,
        clientEphemeralSecretKey: this.pending.clientEphemeralSecretKey,
        expectedServer: this.options.trustedServer,
      });
      const clientAuth = createClientAuth({
        clientHello: this.pending.hello,
        serverHello,
        clientIdentity: this.options.clientIdentity,
      });
      this.nativeSocket.send(serializeSecureControlMessage(clientAuth));
      this.session = session;
      this.readyState = WebSocket.OPEN;
      this.emit("open", makeEvent("open"));
      return;
    }

    const plaintext = decryptSecureFrame(this.session, message as SecureFrame);
    this.emit("message", makeMessageEvent(plaintext));
  }

  private sendBytes(data: Uint8Array): void {
    const session = this.session;
    if (!session) {
      throw new Error("Secure remote WebSocket is not open.");
    }
    this.nativeSocket.send(serializeSecureControlMessage(encryptSecureFrame(session, data)));
  }

  private failHandshake(cause: unknown): void {
    this.emit("error", makeEvent("error"));
    const reason = cause instanceof Error ? cause.message : "Secure remote handshake failed.";
    this.nativeSocket.close(1002, reason.slice(0, 120));
  }

  private emit(type: string, event: Event): void {
    if (type === "open") this.onopen?.call(this as unknown as WebSocket, event);
    else if (type === "message") this.onmessage?.call(this as unknown as WebSocket, event as MessageEvent);
    else if (type === "error") this.onerror?.call(this as unknown as WebSocket, event);
    else if (type === "close") this.onclose?.call(this as unknown as WebSocket, event as CloseEvent);

    const entries = this.listeners.get(type);
    if (!entries) return;
    const remaining: ListenerEntry[] = [];
    for (const entry of entries) {
      if (isListenerObject(entry.listener)) {
        entry.listener.handleEvent(event);
      } else {
        entry.listener.call(this, event);
      }
      if (!entry.once) remaining.push(entry);
    }
    this.listeners.set(type, remaining);
  }
}
