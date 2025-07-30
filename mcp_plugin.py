from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
import webbrowser
from typing import Any, Dict, List, Optional

# These imports are available inside Cutter
import cutter
from PySide6.QtCore import QObject, SIGNAL
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

# Third-party dependencies
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
import uvicorn

# =============================
#          FastAPI Section
# =============================

app = FastAPI(title="Cutter MCP Plugin API", version="0.3.0", docs_url="/docs")

# ---- Adapter for r2/cutter: run in thread pool to avoid blocking event loop ----
async def r2(cmd: str) -> str:
    print(f"[MCP]: {cmd}")
    return await run_in_threadpool(cutter.cmd, cmd)

async def r2j(cmd: str) -> Any:
    out = await r2(cmd)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"json parse failed for '{cmd}': {e}")

# Generic pagination

def paginate(items: List[Dict[str, Any]], offset: int, limit: int) -> Dict[str, Any]:
    total = len(items)
    o = max(int(offset), 0)
    l = max(min(int(limit), 1000), 1)
    return {"items": items[o:o + l], "total": total, "offset": o, "limit": l}

# ---------- Health Check ----------
@app.get("/api/v1/health")
async def health() -> Dict[str, Any]:
    try:
        ver = (await r2("s")).strip()
    except Exception:
        ver = "unknown"
    return {"status": "ok", "r2": {"version": ver}}

# ---------- Data Models (POST JSON Body) ----------
class RenameFunctionReq(BaseModel):
    addr: str
    new_name: str

class CommentReq(BaseModel):
    addr: str
    text: str

class RenameVarReq(BaseModel):
    func_addr: str
    old_name: str
    new_name: str

class SetVarTypeReq(BaseModel):
    func_addr: str
    var_name: str
    new_type: str

class SetProtoReq(BaseModel):
    addr: str
    prototype: str

# ---------- Functions ----------
@app.get("/api/v1/functions")
async def list_functions(offset: int = 0, limit: int = 100) -> Dict[str, Any]:
    funcs = await r2j("aflj") or []
    mapped = [
        {
            "addr": hex(f.get("offset", 0)),
            "name": f.get("name"),
            "size": f.get("size", 0),
            "n_bb": f.get("nbbs", 0),
        }
        for f in funcs
    ]
    return paginate(mapped, offset, limit)

@app.get("/api/v1/functions/detail")
async def function_detail(addr: str) -> Dict[str, Any]:
    info = await r2j(f"afij @ {addr}") or []
    info0 = info[0] if isinstance(info, list) and info else {}
    xrefs_in = await r2j(f"axtj @ {addr}") or []
    return {"info": info0, "xrefs_in": xrefs_in}

@app.post("/api/v1/functions/rename")
async def rename_function(req: RenameFunctionReq) -> Dict[str, Any]:
    if not req.addr or not req.new_name:
        raise HTTPException(status_code=400, detail="addr and new_name are required")
    await r2(f"afn {req.new_name} @ {req.addr}")
    return {"ok": True}

# ---------- Decompilation / Disassembly ----------
@app.get("/api/v1/decompile")
async def decompile(addr: str) -> Dict[str, Any]:
    pseudo = await r2(f"pdg @ {addr}")  # requires r2ghidra/rz-ghidra plugin.. hummm
    return {"addr": addr, "pseudo": pseudo}

@app.get("/api/v1/disasm", response_class=PlainTextResponse)
async def disasm(addr: str, fmt: str = Query("text", pattern="^(text|json)$")):
    if fmt == "json":
        j = await r2j(f"pdfj @ {addr}") or {}
        return json.dumps(j, ensure_ascii=False, indent=2)
    return await r2(f"pdf @ {addr}")

@app.get("/api/v1/pd")
async def pd(addr: str, count: int = Query(32, ge=1, le=4096), fmt: str = Query("text", pattern="^(text|json)$")):
    """Linear disassembly. Returns text by default; JSON for structured ops list.
    - Text: equivalent to `pd {count} @ {addr}`.
    - JSON: equivalent to `pdj {count} @ {addr}`, returns {"addr", "count", "ops":[...]}"""
    if fmt == "json":
        ops = await r2j(f"pdj {count} @ {addr}") or []
        return {"addr": addr, "count": count, "ops": ops}
    text = await r2(f"pdq {count} @ {addr}")
    return PlainTextResponse(text)

# ---------- Strings / Segments / Bytes ----------
@app.get("/api/v1/strings")
async def list_strings(
    offset: int = 0,
    limit: int = 100,
    contains: Optional[str] = None,
    min_length: int = 0,
) -> Dict[str, Any]:
    j = await r2j("izj") or []
    items: List[Dict[str, Any]] = []
    for s in j:
        text = s.get("string", "")
        if contains and contains not in text:
            continue
        if min_length and len(text) < min_length:
            continue
        items.append(
            {
                "addr": hex(s.get("vaddr", 0) or s.get("paddr", 0) or 0),
                "length": s.get("length", 0),
                "type": s.get("type"),
                "string": text,
            }
        )
    return paginate(items, offset, limit)

@app.get("/api/v1/segments")
async def list_segments(offset: int = 0, limit: int = 100) -> Dict[str, Any]:
    segs = await r2j("iSj") or []
    mapped = [
        {
            "name": s.get("name"),
            "vaddr": hex(s.get("vaddr", 0)),
            "paddr": hex(s.get("paddr", 0)),
            "size": s.get("vsize", 0) or s.get("size", 0),
            "perm": s.get("perm"),
        }
        for s in segs
    ]
    return paginate(mapped, offset, limit)

@app.get("/api/v1/bytes")
async def read_bytes(addr: str, size: int = Query(64, ge=1, le=65536)) -> Dict[str, Any]:
    j = await r2j(f"pxj {size} @ {addr}") or []
    return {"addr": addr, "size": size, "bytes": j}

# ---------- Variables / Comments ----------
@app.get("/api/v1/vars")
async def list_vars(addr: str) -> Dict[str, Any]:
    varsj: Any = None
    try:
        varsj = await r2j(f"afvlj @ {addr}")
    except HTTPException:
        varsj = None

    out = {"reg": [], "stack": [], "args": [], "bpvars": []}

    if isinstance(varsj, dict):
        for k in ("reg", "regs", "args", "bpvars", "stack", "vars", "locals"):
            if k in varsj and isinstance(varsj[k], list):
                if k in ("reg", "regs"):
                    out["reg"] = varsj[k]
                elif k in ("vars", "locals", "stack"):
                    out["stack"] = varsj[k]
                else:
                    out[k] = varsj[k]

    return {"addr": addr, "vars": out}

@app.post("/api/v1/comments")
async def set_comment(req: CommentReq) -> Dict[str, Any]:
    if not req.addr:
        raise HTTPException(status_code=400, detail="addr required")
    await r2(f"CCu {json.dumps(req.text)} @ {req.addr}")
    return {"ok": True}

# ---------- Current Position / Shortcuts ----------
@app.get("/api/v1/current/address")
async def current_address() -> Dict[str, Any]:
    val = (await r2("s")).strip()
    try:
        addr = hex(int(val, 16))
    except Exception:
        s_now = (await r2("s")).strip()
        addr = s_now if s_now.startswith("0x") else val
    return {"addr": addr}

@app.get("/api/v1/current/function")
async def current_function() -> Dict[str, Any]:
    info = await r2j("afij @ $$") or []
    return {"info": (info[0] if isinstance(info, list) and info else {})}

# ---------- XREF / Symbols / Entry Points ----------
@app.get("/api/v1/xrefs")
async def xrefs_to(addr: str) -> Dict[str, Any]:
    refs = await r2j(f"axtj @ {addr}") or []
    return {"addr": addr, "xrefs": refs}

@app.get("/api/v1/globals")
async def list_globals(
    offset: int = 0,
    limit: int = 100,
    name_contains: Optional[str] = None,
    typ: Optional[str] = Query(None, description="Filter symbol type, e.g., FUNC/OBJECT/NOTYPE etc."),
) -> Dict[str, Any]:
    syms = await r2j("isj") or []
    items: List[Dict[str, Any]] = []
    for s in syms:
        it = {
            "name": s.get("name"),
            "addr": hex(s.get("vaddr", 0)),
            "paddr": hex(s.get("paddr", 0)),
            "size": s.get("size", 0),
            "bind": s.get("bind"),
            "type": s.get("type"),
        }
        if name_contains and name_contains not in (it["name"] or ""):
            continue
        if typ and (it["type"] or "").upper() != typ.upper():
            continue
        items.append(it)
    return paginate(items, offset, limit)

@app.get("/api/v1/entrypoints")
async def list_entrypoints() -> Dict[str, Any]:
    try:
        eps = await r2j("iej")
    except HTTPException:
        eps = None
    return {"entries": eps or []}

# ---------- Variable Enhancements: Rename / Set Type ----------
async def _with_seek(addr: str, coro):
    cur = (await r2("s")).strip()
    try:
        await r2(f"s {addr}")
        return await coro()
    finally:
        if cur:
            await r2(f"s {cur}")

@app.post("/api/v1/vars/rename")
async def rename_local_variable(req: RenameVarReq) -> Dict[str, Any]:
    if not (req.func_addr and req.old_name and req.new_name):
        raise HTTPException(status_code=400, detail="func_addr, old_name, new_name are required")

    async def _do():
        try:
            await r2(f"afvn {req.new_name} {req.old_name}")
        except Exception:
            await r2(f"afvn {req.old_name} {req.new_name}")
    await _with_seek(req.func_addr, _do)
    return {"ok": True}

@app.post("/api/v1/vars/set_type")
async def set_local_variable_type(req: SetVarTypeReq) -> Dict[str, Any]:
    if not (req.func_addr and req.var_name and req.new_type):
        raise HTTPException(status_code=400, detail="func_addr, var_name, new_type are required")

    async def _do():
        await r2(f"afvt {req.var_name} {req.new_type}")
    await _with_seek(req.func_addr, _do)
    return {"ok": True}

# ---------- Type System / Function Prototypes ----------
@app.get("/api/v1/types")
async def list_types() -> Dict[str, Any]:
    try:
        t = await r2j("tj")
    except HTTPException:
        t = None
    return {"types": t or []}

@app.post("/api/v1/functions/set_prototype")
async def set_function_prototype(req: SetProtoReq) -> Dict[str, Any]:
    if not (req.addr and req.prototype):
        raise HTTPException(status_code=400, detail="addr and prototype are required")
    await r2(f"afs {req.addr} {json.dumps(req.prototype)}")
    return {"ok": True}

# =============================
#       Cutter Plugin Part
# =============================

class UvicornThread(threading.Thread):
    """Run uvicorn.Server in a separate thread for graceful shutdown."""

    def __init__(self, host: str, port: int, log_level: str = "warning"):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.log_level = log_level
        self._server: uvicorn.Server | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._started_evt = threading.Event()

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level=self.log_level,
            access_log=False,
            lifespan="on",
        )
        self._server = uvicorn.Server(config)

        async def serve_and_flag():
            async def wait_port_open():
                for _ in range(100):
                    if self._server.started:
                        self._started_evt.set()
                        return
                    await asyncio.sleep(0.05)
                self._started_evt.set()
            waiter = self._loop.create_task(wait_port_open())
            await self._server.serve()
            await waiter

        try:
            self._loop.run_until_complete(serve_and_flag())
        finally:
            try:
                self._loop.stop()
            except Exception:
                pass
            self._loop.close()

    def stop(self):
        if self._server:
            self._server.should_exit = True
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(lambda: None)

    def wait_started(self, timeout: float = 5.0) -> bool:
        return self._started_evt.wait(timeout)


class MCPDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super().__init__(parent, action)
        self.setObjectName("CutterMCPDock")
        self.setWindowTitle("MCP")

        self._thread: UvicornThread | None = None
        self._status = QLabel("Stopped")
        self._host_input = QLineEdit("127.0.0.1")
        self._port_input = QSpinBox()
        self._port_input.setRange(1000, 65535)
        self._port_input.setValue(8000)
        self._open_docs_chk = QCheckBox("Open API docs on startup")
        self._open_docs_chk.setChecked(False)

        start_btn = QPushButton("Start Server")
        stop_btn = QPushButton("Stop Server")
        health_btn = QPushButton("Health Check")

        start_btn.clicked.connect(self.start_server)
        stop_btn.clicked.connect(self.stop_server)
        health_btn.clicked.connect(self.check_health)

        root = QWidget(self)
        self.setWidget(root)
        v = QVBoxLayout(root)
        v.addWidget(QLabel("Host:"))
        v.addWidget(self._host_input)
        hl = QHBoxLayout()
        hl.addWidget(QLabel("Port:"))
        hl.addWidget(self._port_input)
        v.addLayout(hl)
        v.addWidget(self._open_docs_chk)
        v.addWidget(start_btn)
        v.addWidget(stop_btn)
        v.addWidget(health_btn)
        v.addWidget(QLabel("Status:"))
        v.addWidget(self._status)
        v.addStretch(1)

        QObject.connect(cutter.core(), SIGNAL("seekChanged(RVA)"), self.on_seek_changed)

    def on_seek_changed(self):
        try:
            cur = cutter.cmd("s").strip()
            self._status.setText(f"{self.server_state()}  |  Current Address: {cur}")
        except Exception:
            pass

    def server_state(self) -> str:
        return "🟢 Running" if self._thread and self._thread.is_alive() else "🔴 Stopped"

    def start_server(self):
        if self._thread and self._thread.is_alive():
            self._status.setText("🟢 Already running")
            return
        host = self._host_input.text().strip() or "127.0.0.1"
        port = int(self._port_input.value())
        self._thread = UvicornThread(host, port)
        self._thread.start()
        ok = self._thread.wait_started(5.0)
        self._status.setText("🟢 Running" if ok else "Starting (timeout)")
        if ok and self._open_docs_chk.isChecked() and host == "127.0.0.1":
            webbrowser.open(f"http://127.0.0.1:{port}/docs")

    def stop_server(self):
        if not self._thread:
            self._status.setText("🔴 Stopped")
            return
        self._thread.stop()
        for _ in range(50):
            if not self._thread.is_alive():
                break
            time.sleep(0.05)
        self._thread = None
        self._status.setText("🔴 Stopped")

    def check_health(self):
        host = self._host_input.text().strip() or "127.0.0.1"
        port = int(self._port_input.value())
        try:
            with socket.create_connection((host, port), timeout=0.5):
                ok = True
        except OSError:
            ok = False
        if ok:
            self._status.setText(f"{self.server_state()} | http://{host}:{port}/api/v1/health available")
        else:
            self._status.setText(f"{self.server_state()} | Port not open")

    def closeEvent(self, ev):
        super().closeEvent(ev)

    def shutdown(self):
        self.stop_server()


class CutterMCPPlugin(cutter.CutterPlugin):
    name = "CutterMCP+"
    description = "Expose Cutter/rizin info via a local FastAPI server for MCP"
    version = "0.1.0"
    author = "restkhz"

    def setupPlugin(self):
        self._widget: MCPDockWidget | None = None

    def setupInterface(self, main):
        action = QAction("Cutter MCP Server", main)
        action.setCheckable(True)
        self._widget = MCPDockWidget(main, action)
        main.addPluginDockWidget(self._widget, action)

    def terminate(self):
        if self._widget:
            self._widget.shutdown()
            self._widget = None


def create_cutter_plugin():
    return CutterMCPPlugin()


# --------------CLI Debugging --------------
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--run-server", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()

    if args.run_server:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    else:
        print("This is a Cutter plugin module. Use --run-server to debug FastAPI server.")
