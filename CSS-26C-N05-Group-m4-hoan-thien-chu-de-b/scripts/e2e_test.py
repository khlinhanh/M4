import os
import time
import requests
from requests.exceptions import ConnectionError

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = "ecommerce"
RS1_URL = os.environ.get("RS1_URL", "http://resource-server-1:8000")

def wait_for(url, name, timeout=60):
    print(f"Waiting for {name} at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            if requests.get(url, timeout=2).status_code == 200:
                print(f"{name} is ready.")
                return
        except ConnectionError:
            pass
        time.sleep(2)
    raise TimeoutError(f"{name} did not become ready in time.")

def get_token(username, password):
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": "test-client", 
        "client_secret": "test-secret",
        "grant_type": "password", 
        "username": username, 
        "password": password,
    }
    r = requests.post(url, data=payload)
    if r.status_code != 200:
        print(f"Token Error ({r.status_code}): {r.text}")
    r.raise_for_status()
    return r.json()["access_token"]

def test_rs(token, endpoint, expected_status):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(f"{RS1_URL}{endpoint}", headers=headers, timeout=5)
    assert r.status_code == expected_status, f"Expected {expected_status}, got {r.status_code}"

def main():
    print("=== Starting E2E Tests ===")
    wait_for(f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration", "Keycloak")
    
    # Chờ thêm 5 giây để Keycloak nạp xong user/client
    print("Doi Keycloak khoi tao xong du lieu...")
    time.sleep(5) 

    wait_for(f"{RS1_URL}/health", "Resource Server 1")

    test_rs(None, "/api/user", 401)

    print("-> Testing user role access...")
    user_token = get_token("testuser", "password")
    test_rs(user_token, "/api/user", 200)
    test_rs(user_token, "/api/admin", 403)

    print("-> Testing admin role access...")
    admin_token = get_token("testadmin", "password")
    test_rs(admin_token, "/api/admin", 200)
    
    print("=== ALL E2E TESTS PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
