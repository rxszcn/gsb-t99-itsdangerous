"""一枚在旧摘要年代签出的 token，把签名摘要换掉之后还剩什么读数：14 行。

每行只记现象：换摘要前后各自的 token 能不能验、验的时候派生被跑了几次、
跑的时候用的是哪把密钥与哪一枚摘要、旧摘要在这个构建里不可用时抛什么，
以及这些读数在序列化器 / 带时间戳 / URL 安全这三条路径上是否一致。

用法（在仓库根目录）：
    timeout 120 env PYTHONPATH=src .venv/bin/python <此文件>
"""

import hashlib
from datetime import datetime
from datetime import timezone

from itsdangerous import HMACAlgorithm
from itsdangerous import Signer
from itsdangerous import TimedSerializer
from itsdangerous import TimestampSigner
from itsdangerous import URLSafeSerializer
from itsdangerous.encoding import base64_decode

CHECKS: list[tuple[str, object]] = []


def check(label):
    def deco(fn):
        CHECKS.append((label, fn))
        return fn

    return deco


K = b"secret-key"
KEYS = [b"k1", b"k2", b"k3"]
SALT = b"migration"
OLD = hashlib.sha1  # 起点在用的那一枚
MID = hashlib.sha512  # 更早一版在用的那一枚
NEW = hashlib.sha256  # 要迁过去的那一枚
OTHER = hashlib.sha384  # 两版默认里都没有过的那一枚
_MISSING = object()


def tag_of(digest):
    return {OLD: "old", MID: "mid", NEW: "new", OTHER: "other"}.get(digest, "?")


def signer(digest, key=K, **kw):
    return Signer(key, salt=SALT, digest_method=digest, **kw)


def era_token(digest, key=K, **kw):
    """按「那个年代的配置」签出来的一枚 token。"""
    return signer(digest, key, **kw).sign(b"payload")


def wrong_sig(digest):
    """宽度对、但任何密钥都对不上的一枚签名。"""
    return b"payload." + signer(digest, key=b"not-in-the-list").get_signature(b"payload")


def read(fn, *a, **kw):
    try:
        got = fn(*a, **kw)
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {str(exc)[:52]}"
    return f"{got!r}"[:64]


# ------------------------------------------------------------------ 换摘要之后
@check("F1 换成新摘要之后，旧摘要年代签的 token 仍能验出原值")
def _f1():
    reader = signer(NEW)
    got = read(reader.unsign, era_token(OLD))
    if got != "b'payload'":
        print(f"    旧年代 token {era_token(OLD)!r} -> {got}")
    return got == "b'payload'"


@check("F2 签名段只随新摘要变长（32 字节），旧配置签出的字节一个都没变")
def _f2():
    new_sig = signer(NEW).get_signature(b"payload")
    old_sig = signer(OLD).get_signature(b"payload")
    ok = len(base64_decode(new_sig)) == 32 and len(base64_decode(old_sig)) == 20
    if not ok:
        print(f"    新签名 {new_sig!r} 解出 {len(base64_decode(new_sig))} 字节，"
              f"旧签名 {old_sig!r}")
    return ok


@check("F3 不加任何额外配置的新摘要读端，两代历史默认都还认；两版默认之外的摘要不得顺带被认")
def _f3():
    reader = signer(NEW)
    for name, digest in (("旧", OLD), ("更早", MID)):
        got = read(reader.unsign, era_token(digest))
        if got != "b'payload'":
            print(f"    {name}年代 token -> {got}")
            return False
    never = read(reader.unsign, era_token(OTHER))
    if not never.startswith("BadSignature"):
        print(f"    没有过这一代默认的 token -> {never}")
        return False
    return True


@check("F4 历史摘要可以关掉：关掉后旧 token 验不过，重新登记回来又验得过")
def _f4():
    off = signer(NEW, digest_history=())
    on = signer(NEW, digest_history=(OLD,))
    off_read = read(off.unsign, era_token(OLD))
    on_read = read(on.unsign, era_token(OLD))
    self_read = read(off.unsign, off.sign(b"payload"))
    validate = read(off.validate, era_token(OLD))
    ok = (
        off_read.startswith("BadSignature")
        and on_read == "b'payload'"
        and self_read == "b'payload'"
        and validate == "False"
    )
    if not ok:
        print(f"    关掉={off_read}；登记回来={on_read}；自己的 token={self_read}"
              f"；validate={validate}")
    return ok


# ---------------------------------------------------------------- 一次验证跑多少活
@check("F5 只有与签名同宽的方案参与验证：坏签名的一轮派生次数就是密钥数，不随「还接受几枚摘要」乘出来")
def _f5():
    seen: list[str] = []

    class Probe(Signer):
        def derive_key(self, secret_key=None, **kw):
            seen.append(tag_of(self.digest_method))
            return super().derive_key(secret_key, **kw)

    reader = Probe(KEYS, salt=SALT, digest_method=NEW, digest_history=(OLD, MID, OTHER))
    widths = {}

    for digest in (OTHER, OLD, MID):
        seen.clear()
        read(reader.unsign, wrong_sig(digest))
        widths[tag_of(digest)] = len(seen)

    ok = all(n == len(KEYS) for n in widths.values())
    if not ok:
        print(f"    登记了 4 枚摘要、{len(KEYS)} 把密钥，各宽度实际跑的派生次数 {widths}"
              f"（上界应是密钥数 x 与该宽度同宽的登记数）")
    return ok


@check("F6 两枚同宽摘要都被接受时按 密钥数 x 同宽数 上界，别的宽度只跑一种")
def _f6():
    seen: list[int] = []

    class Probe(Signer):
        def derive_key(self, secret_key=None, **kw):
            seen.append(1)
            return super().derive_key(secret_key, **kw)

    def blake(data=b""):
        return hashlib.blake2b(data, digest_size=32)

    reader = Probe(K, salt=SALT, digest_method=NEW, digest_history=(blake, MID))
    read(reader.unsign, wrong_sig(OLD))
    width20 = len(seen)
    seen.clear()
    read(reader.unsign, wrong_sig(OTHER))
    width48 = len(seen)
    seen.clear()
    read(reader.unsign, wrong_sig(NEW))
    width32 = len(seen)
    ok = (width20, width48, width32) == (1, 1, 2)
    if not ok:
        print(f"    派生次数：20 字节宽={width20}，48 字节宽={width48}，"
              f"32 字节宽={width32}（1 把密钥，接受 new / blake2b-32 同宽两枚 + mid）")
    return ok


@check("F7 旧摘要在本构建里不可用时不得抛穿：构造不碰它，validate 给 False")
def _f7():
    calls = []

    def dead(data=b""):
        calls.append(1)
        raise ValueError("EVP_DigestInit disabled by policy")

    saved_default = Signer.default_digest_method
    saved_history = getattr(Signer, "default_digest_history", _MISSING)
    Signer.default_digest_method = staticmethod(dead)
    Signer.default_digest_history = (dead,)
    try:
        s = Signer(K, salt=SALT)
        at_build = len(calls)
        verdict = read(s.validate, era_token(OLD))
    finally:
        Signer.default_digest_method = saved_default

        if saved_history is _MISSING:
            if hasattr(Signer, "default_digest_history"):
                del Signer.default_digest_history
        else:
            Signer.default_digest_history = saved_history
    ok = at_build == 0 and verdict == "False"
    if not ok:
        print(f"    构造期调用不可用摘要 {at_build} 次；validate(旧年代 token) -> {verdict}")
    return ok


@check("F8 旧摘要不可用的构建上，新摘要这一侧照签照验，验一枚旧 token 报签名不符")
def _f8():
    def dead(data=b""):
        raise ValueError("EVP_DigestInit disabled by policy")

    saved_history = getattr(Signer, "default_digest_history", _MISSING)
    Signer.default_digest_history = (dead, MID)
    try:
        reader = signer(NEW)
        mine = read(reader.unsign, reader.sign(b"payload"))
        old = read(reader.unsign, era_token(OLD))
    finally:
        if saved_history is _MISSING:
            if hasattr(Signer, "default_digest_history"):
                del Signer.default_digest_history
        else:
            Signer.default_digest_history = saved_history
    ok = mine == "b'payload'" and old.startswith("BadSignature")
    if not ok:
        print(f"    自己的 token -> {mine}；旧年代 token -> {old}")
    return ok


# ------------------------------------------------------------- 密钥与派生的归属
@check("F9 最旧那把密钥签的旧摘要 token 也验得过，一枚 token 的尝试次数不乘摘要数")
def _f9():
    seen: list[bytes] = []

    class Probe(Signer):
        def derive_key(self, secret_key=None, **kw):
            seen.append(secret_key or b"<signing-key>")
            return super().derive_key(secret_key, **kw)

    token = era_token(OLD, key=KEYS[0])
    reader = Probe(KEYS, salt=SALT, digest_method=NEW, digest_history=(OLD, MID))
    got = read(reader.unsign, token)
    ok = got == "b'payload'" and seen == [b"k3", b"k2", b"k1"]
    if not ok:
        print(f"    unsign -> {got}；派生依次收到密钥 {seen}")
    return ok


@check("F10 验旧摘要 token 走的还是同一个派生实现（只收密钥的那个形状），验完摘要还是配的那一枚")
def _f10():
    used: list[str] = []

    class Legacy(Signer):
        def derive_key(self, secret_key=None):
            used.append(tag_of(self.digest_method))
            return super().derive_key(secret_key)

    reader = Legacy(K, salt=SALT, digest_method=NEW, digest_history=(OLD,))
    got = read(reader.unsign, era_token(OLD))
    after = tag_of(reader.digest_method)
    ok = got == "b'payload'" and bool(used) and used[-1] == "old" and after == "new"
    if not ok:
        print(f"    unsign -> {got}；派生里看到的摘要依次 {used}；验完 digest_method={after}")
    return ok


@check("F11 显式接管 MAC 算法的读端不再自动接受历史摘要")
def _f11():
    reader = signer(NEW, algorithm=HMACAlgorithm(NEW))
    got = read(reader.unsign, era_token(OLD))
    if not got.startswith("BadSignature"):
        print(f"    algorithm= 的读端 unsign(旧年代 token) -> {got}")
    return got.startswith("BadSignature")


# ---------------------------------------------------------------- 三条继承路径
@check("F12 字典形状的回退条目继承 signer_kwargs：派生方案不丢，非默认摘要也回退得到")
def _f12():
    old_side = URLSafeSerializer(
        K, salt="url", signer_kwargs={"key_derivation": "hmac", "digest_method": OTHER}
    )
    token = old_side.dumps({"id": 42})
    reader = URLSafeSerializer(
        K,
        salt="url",
        signer_kwargs={"key_derivation": "hmac", "digest_method": NEW},
        fallback_signers=[{"digest_method": OTHER}],
    )
    got = read(reader.loads, token)
    if got != "{'id': 42}":
        print(f"    loads -> {got}")
    return got == "{'id': 42}"


@check("F13 每个回退条目只实例化一个 signer，并拿到完整的密钥列表")
def _f13():
    made: list[int] = []

    class Probe(Signer):
        def __init__(self, secret_key, **kw):
            made.append(len(secret_key) if isinstance(secret_key, (list, tuple)) else 1)
            super().__init__(secret_key, **kw)

    reader = URLSafeSerializer(
        KEYS,
        salt="rotate",
        signer=Probe,
        signer_kwargs={"digest_method": OLD},
        fallback_signers=[{"digest_method": OTHER}, {"digest_method": MID}],
    )
    bad = b"payload." + signer(OLD, key=b"other").get_signature(b"payload")
    got = read(reader.loads, bad)
    # 不许按密钥数乘出实例；把回退条目并进主 signer（只建一个）也算通过
    ok = made and made[0] == 3 and all(m == 3 for m in made) and len(made) <= 3
    ok = ok and got.startswith("BadSignature")
    if not ok:
        print(f"    建了 {len(made)} 个 signer 实例，各持密钥数 {made}；loads -> {got}")
    return ok


@check("F14 带时间戳那条路径：旧摘要 token 照常 loads，过期报过期，关掉历史才报签名不符")
def _f14():
    class Aged(TimestampSigner):
        def get_timestamp(self):
            return int(datetime.now(timezone.utc).timestamp()) - 3600

    token = Aged(K, salt=SALT, digest_method=OLD).sign(b"42")
    reader = TimedSerializer(K, salt=SALT, signer_kwargs={"digest_method": NEW})
    plain = read(lambda: reader.loads(token))
    expired = read(lambda: reader.loads(token, max_age=60))
    off = TimedSerializer(
        K, salt=SALT, signer_kwargs={"digest_method": NEW, "digest_history": ()}
    )
    closed = read(lambda: off.loads(token, max_age=60))
    ok = (
        plain == "42"
        and expired.startswith("SignatureExpired")
        and closed.startswith("BadTimeSignature")
    )
    if not ok:
        print(f"    loads -> {plain}；max_age -> {expired}；关掉历史 -> {closed}")
    return ok


print(f"panel: {len(CHECKS)} checks")
passed = 0
for label, fn in CHECKS:
    try:
        ok = bool(fn())
        detail = ""
    except Exception as exc:  # noqa: BLE001
        ok = False
        detail = f" (raised {type(exc).__name__}: {exc})"
    passed += ok
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else detail))
print(f"SUMMARY {passed}/{len(CHECKS)}")
