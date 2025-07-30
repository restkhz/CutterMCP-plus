from __future__ import annotations
import argparse
import json
from typing import Any, Dict, List, Optional

import requests
from mcp.server.fastmcp import FastMCP

BASE = "http://127.0.0.1:8000/api/v1"
TIMEOUT = 10

mcp = FastMCP(name="cuttermcp-plus")

"""
MCP Server: Wraps the local Cutter FastAPI plugin (http://127.0.0.1:8000/api/v1) endpoints into MCP tools usable by LLMs.

Two operating modes:
1) Local development (recommended): STDIO transport, working with OpenAI Agents SDK running the agent locally.
   - Run: python mcp_server.py              # defaults to stdio
   - Connect in Agents SDK with MCPServerStdio(command="python", args=["mcp_server.py"]).
2) Remote/Responses API: Streamable HTTP transport (requires publicly accessible URL).
   - Run: python mcp_server.py --http --port 9000    # starts HTTP /mcp/ endpoint
   - Configure Responses API with tools=[{"type":"mcp","server_url":"https://your-domain/mcp/", ...}]

Note: OpenAI Responses API currently only uses MCP **tools**, not resources/prompts;
      the Agents SDK supports richer capabilities including tool filtering and caching.
"""

# -------------
# Basic HTTP calls
# -------------

def _get(path: str, params: dict | None = None) -> Any:
    url = f"{BASE}{path}"
    r = requests.get(url, params=params or {}, timeout=TIMEOUT)
    r.raise_for_status()
    ct = r.headers.get("content-type", "")
    if "application/json" in ct or path.endswith("json"):
        return r.json()
    return r.text

def _post(path: str, data: dict | None = None) -> Any:
    url = f"{BASE}{path}"
    r = requests.post(url, json=data or {}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json() if "application/json" in r.headers.get("content-type", "") else r.text

# -------------
# Basic functions
# -------------

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 50) -> Dict[str, Any]:
    """List brief information of functions. Returns up to limit items. Use this first to filter targets, then fetch disassembly/decompiled code.
    Returns fields: addr (hex), name, size, n_bb.
    """
    data = _get("/functions", {"offset": offset, "limit": limit})
    return data

@mcp.tool()
def function_detail(addr: str) -> Dict[str, Any]:
    """Get detailed structured information of a single function (address, size, xrefs, etc.). Pass the hexadecimal address string."""
    return _get("/functions/detail", {"addr": addr})

@mcp.tool()
def disasm_by_func_text(addr: str) -> str:
    """Disassemble the entire function as text (pdf) given its address. Recommended, but be cautious of large functions. If this fails, try disasm_text."""
    return _get("/disasm", {"addr": addr, "fmt": "text"})

@mcp.tool()
def disasm_by_func_json(addr: str) -> Dict[str, Any]:
    """Disassemble the entire function as JSON (pdfj). Beware of large functions. If result is null, use text instead."""
    txt = _get("/disasm", {"addr": addr, "fmt": "json"})
    try:
        return json.loads(txt)
    except Exception:
        return {"addr": addr, "json": None}

@mcp.tool()
def decompile(addr: str) -> str:
    """Decompile the function. addr is the address to decompile. If this fails, you can try disasm_text for disassembly."""
    data = _get("/decompile", {"addr": addr})
    return data.get("pseudo", "")

@mcp.tool()
def disasm_text(addr: str, count: int = 64) -> str:
    """Linear disassembly text: from addr, list count instructions, default 64. Can be used as a fallback when disasm_by_func_text fails."""
    return _get("/pd", {"addr": addr, "count": count, "fmt": "text"})

@mcp.tool()
def disasm_json(addr: str, count: int = 64) -> Dict[str, Any]:
    """Linear disassembly in JSON format. Returns {addr, count, ops:[...]}. Default 64 ops."""
    return _get("/pd", {"addr": addr, "count": count, "fmt": "json"})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 100, min_length: int = 0) -> List[Dict[str, Any]]:
    """List strings. Can filter out shorter strings with min_length. Returns fields: addr, length, type, string."""
    data = _get("/strings", {"offset": offset, "limit": limit})
    items = data.get("items", [])
    if min_length > 0:
        items = [s for s in items if s.get("length", 0) >= min_length]
    return items

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """List segments/sections. Returns fields: name, vaddr, paddr, size, perm."""
    data = _get("/segments", {"offset": offset, "limit": limit})
    return data.get("items", [])

@mcp.tool()
def read_bytes(addr: str, size: int = 64) -> Dict[str, Any]:
    """Read raw bytes at the given address. Default size is 64."""
    return _get("/bytes", {"addr": addr, "size": size})

@mcp.tool()
def list_vars(addr: str) -> Dict[str, Any]:
    """List variables/parameters in the function. Returns a variables array."""
    data = _get("/vars", {"addr": addr})
    return data.get("vars", {})

@mcp.tool()
def rename_function(addr: str, new_name: str) -> str:
    """Rename a function."""
    _post("/functions/rename", {"addr": addr, "new_name": new_name})
    return "ok"

@mcp.tool()
def set_comment(addr: str, text: str) -> str:
    """Set a comment at the given address (CCu)."""
    _post("/comments", {"addr": addr, "text": text})
    return "ok"

# ------------------
# Try to aligned with IDA pro mcp XD
# ------------------

@mcp.tool()
def current_address() -> str:
    """Get the currently selected address (hex string)."""
    data = _get("/current/address")
    return data.get("addr", "")

@mcp.tool()
def current_function() -> Dict[str, Any]:
    """Get information of the function containing the current address."""
    data = _get("/current/function")
    return data.get("info", {})

@mcp.tool()
def xrefs_to(addr: str) -> List[Dict[str, Any]]:
    """Get cross-references to a given address."""
    data = _get("/xrefs", {"addr": addr})
    return data.get("xrefs", [])

@mcp.tool()
def list_globals(offset: int = 0, limit: int = 100, name_contains: Optional[str] = None, typ: Optional[str] = None) -> List[Dict[str, Any]]:
    """List global symbols."""
    params: Dict[str, Any] = {"offset": offset, "limit": limit}
    if name_contains:
        params["name_contains"] = name_contains
    if typ:
        params["typ"] = typ
    data = _get("/globals", params)
    return data.get("items", [])

@mcp.tool()
def list_entry_points() -> List[Dict[str, Any]]:
    """List entry points."""
    data = _get("/entrypoints")
    return data.get("entries", [])

@mcp.tool()
def rename_local_variable(func_addr: str, old_name: str, new_name: str) -> str:
    """Rename local variable/parameter."""
    _post("/vars/rename", {"func_addr": func_addr, "old_name": old_name, "new_name": new_name})
    return "ok"

@mcp.tool()
def set_local_variable_type(func_addr: str, var_name: str, new_type: str) -> str:
    """Set local variable type."""
    _post("/vars/set_type", {"func_addr": func_addr, "var_name": var_name, "new_type": new_type})
    return "ok"



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--path", default="/mcp/")
    args = parser.parse_args()

    if args.http:
        mcp.run(transport="http", host=args.host, port=args.port, path=args.path)
    else:
        mcp.run()

if __name__ == "__main__":
    main()
