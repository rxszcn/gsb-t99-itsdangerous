"""边界面板：把 Signer.derive_key() 的字符串 if/elif 分派改成可扩展的方案表之后，
四条内建方案的字节输出、错误类型、以及「方案名」这一字符串标识的作用域是否守住。

用法（在仓库根目录）：
    timeout 120 env PYTHONPATH=src .venv/bin/python <此文件>
"""

import hashlib

from itsdangerous import Signer


CHECKS: list[tuple[str, object]] = []


def check(label):
    def deco(fn):
        CHECKS.append((label, fn))
        return fn

    return deco


GOLDEN = {
    "concat": b"vB06Uuyiib-sD_20h6XV0D2tJ9c",
    "django-concat": b"0qwLB4yD4m_kXZo2U_VvjpPrMp4",
    "hmac": b"gogAs7Pl5nVm2cyMvYP_3C5EpFA",
    "none": b"lPxqL36JuBls904QeajBHrZ5pVI",
}


def sig_for(**kw) -> bytes:
    s = Signer(secret_key=b"k", salt=b"s", **kw)
    return s.get_signature(b"v")


@check("L1 四条内建方案的签名字节与起点黄金值逐位一致")
def _l1():
    got = {name: sig_for(key_derivation=name) for name in GOLDEN}
    return got == GOLDEN


@check("L2 未知方案名抛 TypeError（不是 KeyError/AttributeError）")
def _l2():
    try:
        sig_for(key_derivation="nope")
    except TypeError:
        return True
    except Exception:  # noqa: BLE001
        return False
    return False


@check("L3 内建名的下划线别名不得被接受（字符串标识只有一个规范拼写）")
def _l3():
    try:
        sig_for(key_derivation="django_concat")
    except TypeError:
        return True
    return False


@check("L4 方案名不得触到对象上的其它属性（dunder / 实例属性名一律未知）")
def _l4():
    for name in ("__init__", "__class__", "_class_lookup", "salt", "secret_keys"):
        try:
            got = sig_for(key_derivation=name)
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"    {name} -> {type(exc).__name__}: {exc}")
            return False
        else:
            print(f"    {name} -> 返回签名 {got!r}")
            return False
    return True


@check("L5 子类新增派生方案：不覆盖 derive_key 也能用（可扩展）")
def _l5():
    class My(Signer):
        pass

    added = getattr(Signer, "key_derivations", None)
    if not isinstance(added, dict):
        return False
    My.key_derivations = {**Signer.key_derivations, "xor": lambda s, sk: sk}
    sig = My(secret_key=b"k", salt=b"s", key_derivation="xor").get_signature(b"v")
    return isinstance(sig, bytes) and len(sig) > 0


@check("L6 子类注册方案不得泄漏到基类或别的子类")
def _l6():
    class A(Signer):
        pass

    class B(Signer):
        pass

    if not isinstance(getattr(Signer, "key_derivations", None), dict):
        return False
    base_before = len(Signer.key_derivations)
    A.key_derivations = {**Signer.key_derivations, "only-a": lambda s, sk: b"x" * 32}
    if len(Signer.key_derivations) != base_before:
        return False
    try:
        B(secret_key=b"k", key_derivation="only-a").get_signature(b"v")
    except TypeError:
        return True
    return False


@check("L7 自定义方案必须收到本次实际使用的那把密钥（多密钥轮换）")
def _l7():
    seen: list[bytes] = []

    if not isinstance(getattr(Signer, "key_derivations", None), dict):
        return False
    Signer.key_derivations = {
        **Signer.key_derivations,
        "spy": lambda s, sk: (seen.append(bytes(sk)), sk)[1],
    }
    try:
        first = Signer(secret_key=b"key-A", salt=b"s", key_derivation="spy")
        token = first.sign(b"v")
        seen.clear()
        rot = Signer(secret_key=[b"key-A", b"key-B"], salt=b"s", key_derivation="spy")
        assert rot.unsign(token) == b"v"
    finally:
        del Signer.key_derivations["spy"]
    return seen == [b"key-B", b"key-A"]


@check("L8 内建方案名仍可经 default_key_derivation 类属性指定（既有覆盖点）")
def _l8():
    class MySigner(Signer):
        default_key_derivation = "hmac"

    return (
        MySigner(secret_key=b"k", salt=b"s").get_signature(b"v")
        == sig_for(key_derivation="hmac")
    )


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
