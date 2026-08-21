"""A minimal Chrome DevTools client: enough to evaluate JS in a page."""
import base64, json, os, socket, struct, urllib.request

def http_json(port, path="/json"):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return json.load(r)

class WS:
    def __init__(self, url):
        assert url.startswith("ws://")
        rest = url[5:]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        self.s = socket.create_connection((host, int(port or 80)), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n")
        self.s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(4096)
        assert b"101" in buf.split(b"\r\n")[0], buf[:120]
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def send(self, obj):
        data = json.dumps(obj).encode()
        header = bytearray([0x81])
        n = len(data)
        if n < 126: header.append(0x80 | n)
        elif n < 65536: header.append(0x80 | 126); header += struct.pack(">H", n)
        else: header.append(0x80 | 127); header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        self.s.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk: raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self):
        b0, b1 = self._read(2)
        n = b1 & 0x7f
        if n == 126: n = struct.unpack(">H", self._read(2))[0]
        elif n == 127: n = struct.unpack(">Q", self._read(8))[0]
        return json.loads(self._read(n).decode())

class Page:
    def __init__(self, ws_url):
        self.ws = WS(ws_url); self.n = 0
    def call(self, method, **params):
        self.n += 1
        self.ws.send({"id": self.n, "method": method, "params": params})
        while True:
            m = self.ws.recv()
            if m.get("id") == self.n:
                if "error" in m: raise RuntimeError(m["error"])
                return m.get("result", {})
    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr,
                      returnByValue=True, awaitPromise=True)
        res = r.get("result", {})
        if r.get("exceptionDetails"):
            return {"__error": str(r["exceptionDetails"].get("exception", {}).get("description"))[:300]}
        return res.get("value")
