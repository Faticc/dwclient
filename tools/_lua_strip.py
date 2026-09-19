"""Lua comment/whitespace stripper, lifted verbatim from DwOS's tools/dwosbuild.py.

Vendored rather than imported so this repository builds on its own, without the DwOS
development tree next to it. It is a real lexer -- it never touches the inside of a
string or a long bracket, and keeps the #! line -- and build.py checks its work by
comparing `luac -s` bytecode of the stripped file against the original, so a bug here
fails the build instead of shipping.

Source: https://github.com/Faticc/dwos -> tools/dwosbuild.py
"""

import os
import re
import shutil
import subprocess
import tempfile


def long_bracket(src, i):
    """Если по смещению i начинается [==[ - вернуть (уровень, длина зачина)."""
    if src[i] != "[":
        return None
    j = i + 1
    while j < len(src) and src[j] == "=":
        j += 1
    if j < len(src) and src[j] == "[":
        return j - i - 1, j - i + 1
    return None


def strip_lua(src):
    """Убрать комментарии и лишние пробелы. Возвращает текст без них."""
    out = []           # список (куски строки, беречь ли её как есть)
    cur = []           # кусок: (текст, "code" | "str" | "raw")
    code = []          # копятся подряд идущие знаки кода
    n = len(src)
    i = 0

    def flush():
        if code:
            cur.append(("".join(code), "code"))
            code.clear()

    def endline(keep):
        flush()
        out.append((list(cur), keep))
        cur.clear()

    # строка запуска сохраняется целиком и первой
    if src.startswith("#"):
        j = src.find("\n")
        if j < 0:
            return src
        cur.append((src[:j], "raw"))
        endline(True)
        i = j + 1

    while i < n:
        c = src[i]
        if c == "\n":
            endline(False)
            i += 1
        elif c == "-" and src.startswith("--", i):
            lb = long_bracket(src, i + 2)
            if lb:
                level, head = lb
                close = "]" + "=" * level + "]"
                end = src.find(close, i + 2 + head)
                i = n if end < 0 else end + len(close)
            else:
                j = src.find("\n", i)
                i = n if j < 0 else j
        elif c == "[":
            lb = long_bracket(src, i)
            if lb:
                level, head = lb
                close = "]" + "=" * level + "]"
                end = src.find(close, i + head)
                end = n if end < 0 else end + len(close)
                chunk = src[i:end]
                flush()
                # внутренние переводы строк остаются частью строки-литерала
                pieces = chunk.split("\n")
                for k, piece in enumerate(pieces):
                    cur.append((piece, "raw"))
                    if k < len(pieces) - 1:
                        endline(True)
                i = end
            else:
                code.append(c)
                i += 1
        elif c in "\"'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                if src[j] == "\n":
                    break
                j += 1
            flush()
            cur.append((src[i:j], "str"))
            i = j
        else:
            code.append(c)
            i += 1
    flush()
    if cur:
        endline(False)

    lines = []
    for parts, keep in out:
        txt = squeeze(parts)
        # пустые строки не нужны - кроме тех, что внутри длинной скобки
        if keep or txt:
            lines.append(txt)
    return "\n".join(lines) + "\n"


WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
DIGIT = set("0123456789")
# пары знаков, которые, слипшись, читаются как один: комментарий, длинная
# скобка, метка, составной знак сравнения
STUCK = {("-", "-"), ("[", "["), ("[", "="), (".", "."), (":", ":"),
         ("<", "="), (">", "="), ("=", "="), ("~", "="), ("/", "/"),
         ("<", "<"), (">", ">")}


def glued(l, r):
    """Прочтётся ли пара знаков иначе, если убрать пробел между ними."""
    if not l or not r:
        return False
    if l in WORD and r in WORD:
        return True
    if (l in DIGIT and r == ".") or (l == "." and r in DIGIT):
        return True
    return (l, r) in STUCK


def squeeze(parts):
    """Собрать строку, выбросив пробелы, без которых код читается так же.
    Отступ и хвост уходят целиком, внутри - всё, что не склеит соседей.
    Куски str и raw отдаются как есть: там пробелы значимы."""
    res = []
    for k, (text, kind) in enumerate(parts):
        if kind != "code":
            res.append(text)
            continue
        after = parts[k + 1][0][:1] if k + 1 < len(parts) else ""
        buf = []
        prev = "".join(res)[-1:]
        j, m = 0, len(text)
        while j < m:
            ch = text[j]
            if ch in " \t":
                while j + 1 < m and text[j + 1] in " \t":
                    j += 1
                left = buf[-1] if buf else prev
                right = text[j + 1] if j + 1 < m else after
                if glued(left, right):
                    buf.append(" ")
            else:
                buf.append(ch)
            j += 1
        res.append("".join(buf))
    return "".join(res)


LUAC = None


def dump(path, tmp):
    """Разбор байткода без отладочных данных, номеров строк и адресов: два
    текста, отличающиеся только пробелами и пустыми строками, дают один и
    тот же ответ."""
    r = subprocess.run([LUAC, "-s", "-o", tmp, path], capture_output=True)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout).decode("utf-8", "replace").strip()
    r = subprocess.run([LUAC, "-l", "-l", tmp], capture_output=True)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout).decode("utf-8", "replace").strip()
    # адрес функции в памяти и строки, на которых она открылась и закрылась
    text = re.sub(rb"[0-9A-Fa-f]{8,16}", b"", r.stdout)
    return re.sub(rb"<[^>\n]*:\d+,\d+>", b"", text), None


def luac_same(src_path, out_path):
    """Убедиться, что ужатый файл - та же программа, что исходник."""
    global LUAC
    if LUAC is None:
        LUAC = (shutil.which("luac") or shutil.which("luac5.4")
                or shutil.which("luac5.3") or False)
    if not LUAC:
        return None
    tmp = os.path.join(tempfile.gettempdir(), "dwosbuild.luac")
    a, err = dump(out_path, tmp)
    if err:
        return err
    b, err = dump(src_path, tmp)
    if err:          # исходник и сам не компилируется - это забота автора
        return None
    return None if a == b else "собранный файл читается иначе, чем исходник"
