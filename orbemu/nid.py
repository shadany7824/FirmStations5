"""NIDs: how PlayStation executables name their imports.

Instead of "printf", a PS4 program imports "hcuQgD53UxM". The NID is a hash of the function
name, so a name can always be turned into its NID (but not the other way round):

    sha1(name + 16-byte salt) -> keep the first 8 bytes -> reverse them
    -> base64 with '-' instead of '/' -> drop the '=' padding   (always 11 characters)

In an import table the symbol is stored as "<NID>#<library id>#<module id>"; only the first
part identifies the function.
"""
import base64
import hashlib

SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")


def nid_for(name):
    digest = hashlib.sha1(name.encode() + SALT).digest()[:8][::-1]
    return base64.b64encode(digest).decode().rstrip("=").replace("/", "-")


def split_import_name(symbol):
    """'hcuQgD53UxM#A#B' -> ('hcuQgD53UxM', 'A', 'B'); a plain name gives (name, None, None)."""
    parts = symbol.split("#")
    return parts[0], parts[1] if len(parts) > 1 else None, parts[2] if len(parts) > 2 else None
