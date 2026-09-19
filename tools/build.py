"""Builds the publishable copy of dwclient from the commented sources.

    python tools/build.py [--src .] [--out dist]

Same shape as DwOS's tools/dwosbuild.py, and for the same reasons:

  * strips comments, indentation and space between tokens from the Lua (never touching
    the inside of a string or a long bracket, keeping any #! line);
  * checks the result by comparing `luac -s` bytecode against the original, so a
    stripper bug fails the build instead of shipping;
  * writes manifest.lua with each file's size and CRC32, which install.lua and
    update.lua use to fetch only what changed and to verify what they fetched;
  * says whether the result fits on a floppy, remembering that every file and directory
    costs another 512 bytes of overhead.

Comments are most of these sources by volume, and this program runs on a machine with a
few hundred KB of RAM, so this is not cosmetic: it is the difference between a client
that fits alongside the OS and one that does not.
"""
from __future__ import annotations

import argparse
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lua_strip import luac_same, strip_lua  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLOPPY = 512 * 1024
PER_FILE = 512

NAME = "dwclient"
VERSION = "1.0"
LABEL = "dwclient"

# Never shipped: the tests, this toolchain and the built copy itself.
SKIP_DIRS = {"dist", "tools", ".git"}
SKIP_FILES = {"install.lua"}
SKIP_PREFIX = ("test_",)

# Files the updater must not overwrite once they exist: the two the owner edits. Getting
# this wrong would wipe someone's credentials on a routine update, so session.lua matters
# more here than anything else in the build.
KEEP = ("session.lua", "hwid.lua")


def is_lua_source(rel: str) -> bool:
    return rel.endswith(".lua")


def wanted(rel: str) -> bool:
    head = rel.split("/")[0]
    if head in SKIP_DIRS:
        return False
    base = os.path.basename(rel)
    if base in SKIP_FILES or base.startswith(SKIP_PREFIX):
        return False
    if base.startswith("."):
        return False
    return rel.endswith(".lua") or rel.endswith(".md")


def collect(src_dir: str):
    out = []
    for dirpath, dirnames, filenames in os.walk(src_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src_dir).replace(os.sep, "/")
            if wanted(rel):
                out.append(rel)
    return sorted(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--src", default=HERE)
    parser.add_argument("--out", default=os.path.join(HERE, "dist"))
    args = parser.parse_args(argv)

    src_dir, out_dir = os.path.abspath(args.src), os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    rels = collect(src_dir)
    if not rels:
        sys.exit("nothing to build in " + src_dir)

    entries, problems, dirs = [], [], set()
    raw_total = total = 0

    for rel in rels:
        src_path = os.path.join(src_dir, rel.replace("/", os.sep))
        with open(src_path, "rb") as f:
            raw = f.read()
        raw_total += len(raw)

        if is_lua_source(rel):
            # strip_lua squeezes as it goes and hands back finished text.
            text = raw.decode("utf-8").replace("\r\n", "\n")
            data = strip_lua(text).encode("utf-8")
        else:
            data = raw

        out_path = os.path.join(out_dir, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)

        if is_lua_source(rel):
            err = luac_same(src_path, out_path)
            if err:
                problems.append((rel, err))

        parent = os.path.dirname(rel)
        while parent:
            dirs.add(parent)
            parent = os.path.dirname(parent)

        total += len(data)
        entries.append((rel, len(data), "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)))

    # install.lua doubles as the updater: the installed copy keeps a stripped version of
    # the very same program next to the client, so "update" needs nothing downloaded
    # first. It is excluded from the walk above only so it is not shipped twice.
    installer = os.path.join(src_dir, "install.lua")
    if not os.path.exists(installer):
        # Repository layout: sources in src/, the installer at the root next to it.
        installer = os.path.join(os.path.dirname(src_dir), "install.lua")
    if os.path.exists(installer):
        with open(installer, "rb") as f:
            text = f.read().decode("utf-8").replace("\r\n", "\n")
        data = strip_lua(text).encode("utf-8")
        out_path = os.path.join(out_dir, "update.lua")
        with open(out_path, "wb") as f:
            f.write(data)
        err = luac_same(installer, out_path)
        if err:
            problems.append(("update.lua", err))
        total += len(data)
        entries.append(("update.lua", len(data), "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)))
        entries.sort(key=lambda e: e[0])

    if problems:
        for rel, err in problems:
            print("  !! %s: %s" % (rel, err))
        sys.exit("build failed its own bytecode check")

    width = max(len(rel) for rel, _, _ in entries) + 3
    lines = [
        "-- What gets installed, and how it is verified. size and crc are written by",
        "-- tools/build.py -- do not edit by hand: the installer checks downloads against them.",
        "{",
        '\tname = "%s",' % NAME,
        '\tversion = "%s",' % VERSION,
        '\tlabel = "%s",' % LABEL,
        "\tkeep = { " + ", ".join('"%s"' % k for k in KEEP) + " },",
        "\tfiles = {",
    ]
    for rel, size, crc in entries:
        lines.append('\t\t{ %s size = %d, crc = "%s" },' % (('"%s",' % rel).ljust(width), size, crc))
    lines.append("\t},")
    lines.append("}")
    manifest = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "manifest.lua"), "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest)

    nfiles = len(entries) + 1
    total += len(manifest.encode("utf-8"))
    on_floppy = total + PER_FILE * (nfiles + len(dirs))
    print("sources: %d files, %d bytes" % (len(entries), raw_total))
    print("built:   %d files, %d bytes  (-%d%%)"
          % (nfiles, total, round(100 - total * 100.0 / raw_total)))
    print("on a floppy: %d of %d bytes (%d directories)%s"
          % (on_floppy, FLOPPY, len(dirs), "" if on_floppy <= FLOPPY else "  -- DOES NOT FIT"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
