from mimetypes import MimeTypes
from pathlib import Path

from connection.virtual_http import HTTPResponse, VirtualHTTPServer

# A private table keeps Python's types; the global one reads the Windows
# registry, where .js may be registered as text/plain and browsers refuse it.
MIME_TYPES = MimeTypes()


def content_type(file: Path) -> str:
    mime_type = MIME_TYPES.guess_type(file.name, strict=False)[0]
    if not mime_type: return 'application/octet-stream'
    return mime_type + '; charset=utf-8' if mime_type[:5] == 'text/' else mime_type


def static_files(root: Path) -> dict[str, tuple[bytes, str]]:
    files = {}
    for file in sorted(root.rglob('*')):
        if not file.is_file() or file.name[0] == '.': continue
        path = '/' + file.relative_to(root).as_posix()
        files[path] = file.read_bytes(), content_type(file)
    if '/index.html' in files: files['/'] = files['/index.html']
    return files


def register_static(http: VirtualHTTPServer, root: Path):
    # Files are read once here; serving them never touches the disk.
    for path, (body, mime_type) in static_files(root).items():
        headers = {'Content-Type': mime_type, 'Cache-Control': 'no-cache'}
        handler = lambda request, body=body, headers=headers: \
            HTTPResponse(body, headers=headers)
        http.add_route('GET', path, handler)
