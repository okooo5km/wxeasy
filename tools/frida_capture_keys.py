#!/usr/bin/env python3
"""
WeChat Windows 4.1.10+ dynamic DB key capture via Frida.

Why:
  4.1.10+ enables SQLCipher cipher_memory_security-style key residency.
  Steady-state process memory almost never contains raw 32-byte DB keys.
  When a DB is actually unlocked/used, OpenSSL AES-NI set-key is called with
  the raw AES-256 userKey — that is the capture window.

Method:
  1. Attach to the Weixin.exe process that loaded Weixin.dll
  2. Pattern-locate aesni_set_encrypt_key inside Weixin.dll (and roam_server.dll)
  3. Hook calls with bits==256, read 32-byte userKey from RCX
  4. page1-verify each candidate against local encrypted DBs
  5. Optionally merge verified keys into ~/.wxeasy/all_keys.json

Requirements:
  - Python 3.9+ (Frida 16.5.x works on 3.9; newer Frida may need newer Python)
  - pip install frida==16.5.9 pycryptodome
  - WeChat logged in; exercise UI (chats / contacts / moments / favorites)
    so more DB modules materialize keys
  - Prefer running this shell as Administrator for OpenProcess reliability

Usage:
  python tools/frida_capture_keys.py
  python tools/frida_capture_keys.py --seconds 120 --db-dir "D:/wechat/xwechat_files/<id>/db_storage"
  python tools/frida_capture_keys.py --merge   # write verified keys into ~/.wxeasy/all_keys.json

Tested on: Weixin 4.1.11.24 (Windows x64)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import frida
except ImportError:
    print("missing frida — pip install frida==16.5.9", file=sys.stderr)
    sys.exit(1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("missing pycryptodome — pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

PAGE, RESERVE = 4096, 80
META = bytes([0x10, 0x00, 0x02, 0x02, 0x50, 0x40, 0x20, 0x20])
DEFAULT_KEYS = Path.home() / ".wxeasy" / "all_keys.json"

# OpenSSL aesni_set_encrypt_key prolog (x64), observed on 4.1.11.24:
#   sub rsp, 8
#   mov rax, -1
#   test rcx, rcx
PROLOG_PATTERN = "48 83 ec 08 48 c7 c0 ff ff ff ff 48 85 c9"

JS = r"""
'use strict';
const PROLOG = '%PROLOG%';

function hex(p, n) {
  try {
    const b = new Uint8Array(p.readByteArray(n));
    let h = '';
    for (let i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
    return h;
  } catch (e) { return null; }
}

function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).map(String).slice(0, 8); }
  catch (e) { return []; }
}

const seen = {};
const hooked = [];

function hookAesni(modName) {
  const m = Process.findModuleByName(modName);
  if (!m) {
    send({ t: 'status', msg: 'module not loaded: ' + modName });
    return;
  }
  let hits;
  try {
    hits = Memory.scanSync(m.base, m.size, PROLOG);
  } catch (e) {
    send({ t: 'err', msg: 'scan ' + modName + ' ' + e });
    return;
  }
  send({ t: 'status', msg: modName + ' base=' + m.base + ' prolog_hits=' + hits.length });
  // Prefer the hit whose body has cmp edx, 0x100 nearby (AES-256 branch)
  const chosen = [];
  for (const h of hits) {
    try {
      const window = new Uint8Array(h.address.readByteArray(0x80));
      let ok = false;
      for (let i = 0; i + 5 < window.length; i++) {
        // 81 fa 00 01 00 00  cmp edx, 0x100
        if (window[i] === 0x81 && window[i+1] === 0xfa &&
            window[i+2] === 0x00 && window[i+3] === 0x01 &&
            window[i+4] === 0x00 && window[i+5] === 0x00) {
          ok = true; break;
        }
      }
      if (ok) chosen.push(h.address);
    } catch (e) {}
  }
  if (!chosen.length) {
    // fallback: first few prolog hits
    for (const h of hits.slice(0, 3)) chosen.push(h.address);
  }
  for (const addr of chosen) {
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          let bits = 0;
          try { bits = this.context.rdx.toInt32(); } catch (e) {}
          if (bits !== 256) return;
          const key = hex(this.context.rcx, 32);
          if (!key || seen[key]) return;
          seen[key] = 1;
          send({
            t: 'key',
            mod: modName,
            at: addr.toString(),
            rva: addr.sub(m.base).toString(16),
            key: key,
            bt: bt(this.context)
          });
        }
      });
      hooked.push(modName + '@' + addr);
    } catch (e) {
      send({ t: 'err', msg: 'hook ' + addr + ' ' + e });
    }
  }
}

hookAesni('Weixin.dll');
hookAesni('roam_server.dll');
send({ t: 'ready', hooked: hooked });

rpc.exports = {
  n: function () { return Object.keys(seen).length; },
  keys: function () { return Object.keys(seen); }
};
""".replace("%PROLOG%", PROLOG_PATTERN)


def S(x, n=240):
    return str(x).encode("ascii", "backslashreplace").decode("ascii")[:n]


def verify(key: bytes, page: bytes) -> bool:
    if len(key) != 32 or len(page) < PAGE:
        return False
    iv = page[PAGE - RESERVE : PAGE - RESERVE + 16]
    enc = page[16 : PAGE - RESERVE]
    try:
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
    except Exception:
        return False
    return dec[:8] == META


def load_dbs(db_dir: Path):
    dbs = []
    if not db_dir.exists():
        return dbs
    for p in db_dir.rglob("*.db"):
        if p.name.endswith(("-wal", "-shm")):
            continue
        try:
            page = p.read_bytes()[:PAGE]
        except OSError:
            continue
        if len(page) < PAGE:
            continue
        # skip plaintext sqlite
        if page.startswith(b"SQLite format 3"):
            continue
        name = str(p.relative_to(db_dir)).replace("\\", "/")
        dbs.append((name, page))
    return dbs


def resolve_db_dir(cli: str | None) -> Path:
    if cli:
        return Path(cli)
    cfg = Path.home() / ".wxeasy" / "config.json"
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            d = data.get("db_dir") or data.get("dbDir")
            if d:
                return Path(d)
        except Exception:
            pass
    # common fallbacks
    for base in [
        Path.home() / "Documents" / "xwechat_files",
        Path.home() / "文档" / "xwechat_files",
        Path("D:/wechat/xwechat_files"),
    ]:
        if not base.exists():
            continue
        cands = list(base.glob("*/db_storage"))
        if cands:
            return cands[0]
    return Path.home() / "Documents" / "xwechat_files"


def find_main_pid(device):
    for p in device.enumerate_processes():
        if p.name.lower() != "weixin.exe":
            continue
        try:
            s = device.attach(p.pid)
            sc = s.create_script(
                "rpc.exports={has:function(){return Process.enumerateModules()"
                ".some(m=>m.name.toLowerCase()==='weixin.dll');}};"
            )
            sc.load()
            ok = sc.exports_sync.has()
            sc.unload()
            s.detach()
            if ok:
                return p.pid
        except Exception as e:
            print("probe pid", p.pid, S(e))
    return None


def merge_keys(path: Path, verified: dict):
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    changed = 0
    for name, key in verified.items():
        cur = existing.get(name)
        old = None
        if isinstance(cur, dict):
            old = cur.get("enc_key")
        elif isinstance(cur, str):
            old = cur
        if old == key:
            continue
        existing[name] = {"enc_key": key, "source": "frida_aesni_set_key"}
        changed += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return changed, len(existing)


def main():
    ap = argparse.ArgumentParser(description="Capture WeChat 4.1.10+ DB keys via Frida AES-NI set-key hook")
    ap.add_argument("--seconds", type=int, default=90, help="capture window seconds (default 90)")
    ap.add_argument("--db-dir", type=str, default=None, help="path to account db_storage")
    ap.add_argument("--pid", type=int, default=0, help="attach specific Weixin.exe pid")
    ap.add_argument("--out", type=str, default="captured_keys.json", help="write verified keys JSON")
    ap.add_argument("--merge", action="store_true", help="merge verified keys into ~/.wxeasy/all_keys.json")
    ap.add_argument("--keys-file", type=str, default=str(DEFAULT_KEYS), help="all_keys.json path for --merge")
    args = ap.parse_args()

    db_dir = resolve_db_dir(args.db_dir)
    dbs = load_dbs(db_dir)
    print("db_dir", db_dir)
    print("encrypted dbs", len(dbs))
    if not dbs:
        print("WARNING: no encrypted dbs found — verification will be empty", file=sys.stderr)

    device = frida.get_local_device()
    pid = args.pid or find_main_pid(device)
    print("attach pid", pid)
    if not pid:
        print("no Weixin.exe with Weixin.dll loaded — start WeChat and login first", file=sys.stderr)
        return 1

    session = device.attach(pid)
    verified: dict[str, str] = {}
    all_keys: list[str] = []
    keyset = set()

    def on_msg(message, data):
        if message["type"] != "send":
            print("ERR", S(message))
            return
        p = message["payload"]
        t = p.get("t")
        if t in ("status", "ready", "err"):
            print(t.upper(), S(p))
            return
        if t != "key":
            return
        kh = (p.get("key") or "").lower()
        if len(kh) != 64 or kh in keyset:
            return
        keyset.add(kh)
        all_keys.append(kh)
        print("KEY#%d %s rva=0x%s %s" % (len(all_keys), p.get("mod"), p.get("rva"), kh))
        kb = bytes.fromhex(kh)
        for name, page in dbs:
            if name in verified:
                continue
            if verify(kb, page):
                verified[name] = kh
                print("  VERIFY", name)

    script = session.create_script(JS)
    script.on("message", on_msg)
    script.load()
    print(
        "capturing %ds — open chats, contacts, moments, favorites, search..."
        % args.seconds
    )
    for i in range(args.seconds):
        time.sleep(1)
        if (i + 1) % 10 == 0:
            try:
                n = script.exports_sync.n()
            except Exception:
                n = "?"
            print("...%ds unique=%s verified=%d/%d" % (i + 1, n, len(verified), len(dbs)))

    try:
        session.detach()
    except Exception:
        pass

    out = {
        "db_dir": str(db_dir),
        "pid": pid,
        "unique_aes256_keys": len(all_keys),
        "verified": verified,
        "missing": [n for n, _ in dbs if n not in verified],
    }
    out_path = Path(args.out)
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out_path.resolve())
    print("DONE verified", len(verified), "/", len(dbs), "unique_keys", len(all_keys))
    for name, key in sorted(verified.items()):
        print(" ", name, key)

    if args.merge and verified:
        nchg, ntot = merge_keys(Path(args.keys_file), verified)
        print("merged into", args.keys_file, "changed", nchg, "total", ntot)
        print("next: wxeasy init   # reuse/verify into config")

    if not verified:
        print(
            "\nNo DB keys verified. Tips:\n"
            "  - Keep WeChat in foreground; open message history / contacts / moments\n"
            "  - Run longer: --seconds 180\n"
            "  - Confirm --db-dir points at the logged-in account's db_storage\n"
            "  - Try Administrator shell\n"
            "  - Best coverage: start capture, then switch accounts or re-login",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
