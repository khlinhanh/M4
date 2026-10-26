"""Moi ham test = mot khang dinh an toan ve cau hinh realm (doc truc tiep config/keycloak/realm.json).
Khong can Keycloak chay. Day la kiem tinh, khong thay the kiem thu tuong tac voi Keycloak that."""
import json
from pathlib import Path

import pytest

REALM = json.loads(
    (Path(__file__).resolve().parents[1] / "config" / "keycloak" / "realm.json").read_text(encoding="utf-8")
)
CLIENTS = {c["clientId"]: c for c in REALM["clients"]}
FLOWS = {f["alias"]: f for f in REALM["authenticationFlows"]}
APPS = [("app1", "app1-api"), ("app2", "app2-api"), ("app3", "app3-api")]


def _exec(flow, **kw):
    for e in FLOWS[flow]["authenticationExecutions"]:
        if all(e.get(k) == v for k, v in kw.items()):
            return e
    return None


# --- Chiem phien / token song qua lau -------------------------------------
def test_access_token_song_300_giay():
    assert REALM["accessTokenLifespan"] == 300

def test_sso_idle_900_giay():
    assert REALM["ssoSessionIdleTimeout"] == 900

def test_sso_toi_da_36000_giay():
    assert REALM["ssoSessionMaxLifespan"] == 36000

def test_client_session_idle_900_giay():
    assert REALM["clientSessionIdleTimeout"] == 900

def test_client_session_toi_da_36000_giay():
    assert REALM["clientSessionMaxLifespan"] == 36000

def test_refresh_token_xoay_vong():
    assert REALM["revokeRefreshToken"] is True

def test_refresh_token_khong_dung_lai():
    assert REALM["refreshTokenMaxReuse"] == 0

def test_chu_ky_mac_dinh_rs256():
    assert REALM["defaultSignatureAlgorithm"] == "RS256"

@pytest.mark.parametrize("app,_api", APPS)
def test_pkce_s256_bat_buoc(app, _api):
    assert CLIENTS[app]["attributes"]["pkce.code.challenge.method"] == "S256"

@pytest.mark.parametrize("app,_api", APPS)
def test_khong_cap_token_bang_mat_khau_truc_tiep(app, _api):
    assert CLIENTS[app]["directAccessGrantsEnabled"] is False

# --- Sai doi tuong nhan (audience) ----------------------------------------
@pytest.mark.parametrize("app,api", APPS)
def test_audience_rieng_trong_access_token(app, api):
    auds = {m["config"]["included.client.audience"]
            for m in CLIENTS[app]["protocolMappers"]
            if m["protocolMapper"] == "oidc-audience-mapper"
            and m["config"]["access.token.claim"] == "true"}
    assert auds == {api}

@pytest.mark.parametrize("app,_api", APPS)
def test_audience_khong_vao_id_token(app, _api):
    for m in CLIENTS[app]["protocolMappers"]:
        assert m["config"]["id.token.claim"] == "false"

@pytest.mark.parametrize("_app,api", APPS)
def test_client_api_chi_nhan_bearer(_app, api):
    assert CLIENTS[api]["bearerOnly"] is True

# --- Khoi phuc mat khau bi lam dung / brute force --------------------------
def test_tu_phuc_hoi_mat_khau_tat():
    assert REALM["resetPasswordAllowed"] is False

def test_brute_force_bat():
    assert REALM["bruteForceProtected"] is True

def test_khoa_sau_5_lan_that_bai():
    assert REALM["failureFactor"] == 5

# --- TOTP bat buoc cho admin ----------------------------------------------
def test_browser_flow_la_flow_admin_totp():
    assert REALM["browserFlow"] == "Browser with admin TOTP"

def test_otp_la_totp_6_so_30_giay():
    assert (REALM["otpPolicyType"], REALM["otpPolicyDigits"], REALM["otpPolicyPeriod"]) == ("totp", 6, 30)

def test_ma_otp_khong_dung_lai():
    assert REALM["otpPolicyCodeReusable"] is False

def test_nhanh_totp_la_conditional():
    assert _exec("Browser login forms", flowAlias="Admin TOTP")["requirement"] == "CONDITIONAL"

def test_dieu_kien_kiem_role_admin_khong_phu_dinh():
    cfg = next(c for c in REALM["authenticatorConfig"] if c["alias"] == "admin-role-condition")["config"]
    assert (cfg["condUserRole"], cfg["negate"]) == ("admin", "false")

def test_otp_form_bat_buoc():
    assert _exec("Admin TOTP", authenticator="auth-otp-form")["requirement"] == "REQUIRED"

def test_chi_hai_role_user_va_admin():
    assert {r["name"] for r in REALM["roles"]["realm"]} == {"user", "admin"}

# --- Gioi han da biet (kiem de khong bao cao sai) --------------------------
def test_redirect_uri_van_la_wildcard_localhost__gioi_han_da_biet():
    """Khang dinh nguoc co chu y: khop voi muc 'Gioi han' trong bao cao. Neu doi sang callback
    chinh xac thi test nay phai doi cung bao cao."""
    assert all(u.endswith("/*") for a, _ in APPS for u in CLIENTS[a]["redirectUris"])
