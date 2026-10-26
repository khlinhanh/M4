"""Ca tan cong song: gui token doc hai vao tung resource server DANG CHAY, ghi ket qua.

Chi dung HTTP loopback toi container cua chinh nhom (README muc 7).
Ket qua hop le = HTTP 401 hoac 403. Moi ma khac (ke ca 404 do sai duong dan) bi ghi la
KHONG DAT, de tranh ket luan sai.

Bien moi truong:
  RS_PATH   duong dan API can bao ve. Neu bo trong, script do cac duong dan ung vien va chon
            duong dan dau tien tra 401/403 khi KHONG co token. CAN XAC NHAN theo app.py.
  RS_PORTS  danh sach cong, mac dinh 8001,8002,8003
Ca "sai audience voi chu ky hop le" can token that tu Keycloak nen KHONG nam o day;
no duoc kiem boi unit test (test_rejects_wrong_audience, test_rejects_app3_audience).
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "evidence" / "attack-results.json"
CANDIDATES = [p for p in [os.environ.get("RS_PATH")] if p] or ["/api/user", "/user", "/api/me", "/me", "/api/profile"]
PATH = CANDIDATES[0]
PORTS = [int(p) for p in os.environ.get("RS_PORTS", "8001,8002,8003").split(",")]
ISS = "http://localhost:8080/realms/ecommerce"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(header: dict, payload: dict, sig: bytes = b"") -> str:
    return ".".join([b64(json.dumps(header).encode()), b64(json.dumps(payload).encode()), b64(sig)])


def claims(aud: str) -> dict:
    now = int(time.time())
    return {"iss": ISS, "aud": aud, "sub": "attacker", "iat": now, "exp": now + 300,
            "realm_access": {"roles": ["admin"]}}


def cases(n: int) -> dict:
    aud = f"app{n}-api"
    other = f"app{n % 3 + 1}-api"
    hs_key = b"khoa-gia-tuy-y"
    hs_head = {"alg": "HS256", "typ": "JWT"}
    hs_body = b64(json.dumps(hs_head).encode()) + "." + b64(json.dumps(claims(aud)).encode())
    hs_sig = hmac.new(hs_key, hs_body.encode(), hashlib.sha256).digest()
    return {
        "khong_co_token": None,
        "alg_none_dung_audience": jwt({"alg": "none", "typ": "JWT"}, claims(aud)),
        "alg_none_sai_audience": jwt({"alg": "none", "typ": "JWT"}, claims(other)),
        "chu_ky_RS256_gia": jwt({"alg": "RS256", "typ": "JWT"}, claims(aud), b"chu-ky-gia"),
        "HS256_khoa_tuy_y": hs_body + "." + b64(hs_sig),
        "token_rac": "khong.phai.jwt",
    }


def call(port: int, token):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{PATH}")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # dich vu khong chay
        return f"LOI:{type(e).__name__}"


def detect_path() -> str:
    for p in CANDIDATES:
        global PATH
        PATH = p
        if call(PORTS[0], None) in (401, 403):
            return p
    print("LOI: khong tim duoc duong dan API duoc bao ve. Dat RS_PATH theo ma nguon "
          "resource server (xem app.py) roi chay lai.", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    results, failed = [], 0
    detect_path()
    print(f"Duong dan API dung de tan cong: {PATH}")
    for i, port in enumerate(PORTS, start=1):
        for name, tok in cases(i).items():
            code = call(port, tok)
            ok = code in (401, 403)
            failed += 0 if ok else 1
            results.append({"resource_server": i, "port": port, "path": PATH,
                            "case": name, "http": code, "expected": "401|403",
                            "result": "DAT" if ok else "KHONG DAT"})
            print(f"RS{i} {name:26s} -> {code}  {'DAT' if ok else 'KHONG DAT'}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Tong: {len(results)} ca, {failed} khong dat -> {OUT.relative_to(Path(__file__).resolve().parents[1])}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
