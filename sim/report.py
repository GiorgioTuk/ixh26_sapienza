from dataclasses import dataclass

OK, FAIL, WARN, SKIP = "OK", "FAIL", "WARN", "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


def check(name: str, passed: bool, detail_ok: str = "", detail_fail: str = "") -> Check:
    return Check(name, OK if passed else FAIL, detail_ok if passed else detail_fail)


def verdict(checks: list[Check]) -> str:
    if any(c.status == FAIL for c in checks):
        return "REJECTED"
    if any(c.status == WARN for c in checks):
        return "VERIFIED WITH WARNINGS"
    return "VERIFIED"
