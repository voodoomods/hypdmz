"""The proxy reads a whole request before it forwards one.

A plain-HTTP request was forwarded as the first socket read had it. When the client sent the headers and the body
apart, the model received no body and answered 400: a swarm on a plain-HTTP model (a llama-server on the LAN) lost
about half its calls. The HTTPS path already read by Content-Length; the plain path now does too.

The reader is taken out of main.py by name, so this runs without the proxy image's packages.
"""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "hypdmz" / "images" / "proxy" / "app" / "main.py"
TREE = ast.parse(MAIN.read_text(encoding="utf-8"))
BODY = b'{"model": "m", "messages": [{"role": "user", "content": "hi"}]}'
HEAD = (b"POST http://10.0.0.5:8080/v1/chat/completions HTTP/1.1\r\nHost: 10.0.0.5:8080\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n")


def _reader_fn():
    fn = next(n for n in TREE.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_read_full_request")
    ns: dict = {"asyncio": asyncio}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(MAIN), "exec"), ns)
    return ns["_read_full_request"]


def _read(first: bytes, later: list[bytes]) -> bytes:
    async def go() -> bytes:
        reader = asyncio.StreamReader()
        for chunk in later:
            reader.feed_data(chunk)
        reader.feed_eof()
        return await _reader_fn()(reader, timeout=2.0, first=first)
    return asyncio.run(go())


def test_a_body_sent_after_the_headers_is_read():
    assert _read(HEAD, [BODY]) == HEAD + BODY


def test_a_body_sent_in_pieces_is_read_whole():
    assert _read(HEAD + BODY[:10], [BODY[10:30], BODY[30:]]) == HEAD + BODY


def test_headers_cut_by_the_first_read_are_finished():
    assert _read(HEAD[:40], [HEAD[40:] + BODY]) == HEAD + BODY


def test_a_request_already_whole_is_returned_as_it_is():
    assert _read(HEAD + BODY, []) == HEAD + BODY
    get = b"GET http://10.0.0.5:8080/v1/models HTTP/1.1\r\nHost: 10.0.0.5:8080\r\n\r\n"
    assert _read(get, []) == get


def test_both_paths_read_the_whole_request():
    handler = next(n for n in TREE.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "handle_client")
    calls = [n for n in ast.walk(handler) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_read_full_request"]
    assert len(calls) == 2                                # the decrypted HTTPS path, and the plain path
    assert any(k.arg == "first" for c in calls for k in c.keywords)
