import base64
import hashlib
import time
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app as demo_app


ISSUER = "http://localhost:8080/realms/ecommerce"
DISCOVERY = {
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
}


class OidcFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    def setUp(self):
        demo_app.sessions.clear()
        self.client = TestClient(demo_app.app)

    def test_login_uses_authorization_code_and_pkce_s256(self):
        with patch("app.requests.get") as get:
            get.return_value.json.return_value = DISCOVERY
            response = self.client.get("/login", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        params = parse_qs(urlparse(response.headers["location"]).query)
        self.assertEqual(params["client_id"], ["app1"])
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["redirect_uri"], ["http://localhost:3001/callback"])
        self.assertEqual(len(params["state"][0]), 43)
        self.assertEqual(len(params["nonce"][0]), 43)

    def test_callback_validates_state_nonce_and_calls_own_resource_server(self):
        with patch("app.requests.get") as get:
            get.return_value.json.return_value = DISCOVERY
            login_response = self.client.get("/login", follow_redirects=False)
        authorization_params = parse_qs(
            urlparse(login_response.headers["location"]).query
        )

        session_id = self.client.cookies[demo_app.SESSION_COOKIE]
        pending = demo_app.sessions[session_id]["pending"]
        now = int(time.time())
        id_token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": "app1",
                "sub": "test-user",
                "preferred_username": "test-user",
                "iat": now,
                "exp": now + 300,
                "nonce": pending["nonce"],
            },
            self.private_key,
            algorithm="RS256",
        )
        token_reply = Mock()
        token_reply.json.return_value = {
            "access_token": "opaque-access-token",
            "id_token": id_token,
        }

        with (
            patch("app.requests.get") as get,
            patch("app.requests.post", return_value=token_reply) as post,
            patch("app.PyJWKClient") as jwks_client,
        ):
            get.return_value.json.return_value = DISCOVERY
            jwks_client.return_value.get_signing_key_from_jwt.return_value.key = (
                self.private_key.public_key()
            )
            response = self.client.get(
                "/callback",
                params={"code": "authorization-code", "state": pending["state"]},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        exchanged = post.call_args.kwargs["data"]
        self.assertEqual(exchanged["client_id"], "app1")
        self.assertEqual(exchanged["redirect_uri"], "http://localhost:3001/callback")
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(exchanged["code_verifier"].encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(
            challenge,
            authorization_params["code_challenge"][0],
        )

        with patch("app.requests.get") as api_get:
            api_get.return_value.status_code = 200
            api_get.return_value.text = '{"message":"User API access granted"}'
            result = self.client.get("/call/user")
        self.assertEqual(result.status_code, 200)
        self.assertIn("User API access granted", result.text)
        self.assertEqual(
            api_get.call_args.args[0],
            "http://resource-server-1:8000/api/user",
        )
        self.assertEqual(
            api_get.call_args.kwargs["headers"]["Authorization"],
            "Bearer opaque-access-token",
        )

    def test_callback_rejects_state_mismatch_before_token_exchange(self):
        with patch("app.requests.get") as get:
            get.return_value.json.return_value = DISCOVERY
            self.client.get("/login", follow_redirects=False)

        with patch("app.requests.post") as post:
            response = self.client.get(
                "/callback",
                params={"code": "authorization-code", "state": "wrong-state"},
            )

        self.assertEqual(response.status_code, 400)
        post.assert_not_called()

    def test_id_token_rejects_wrong_nonce(self):
        now = int(time.time())
        id_token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": "app1",
                "sub": "test-user",
                "iat": now,
                "exp": now + 300,
                "nonce": "different-nonce",
            },
            self.private_key,
            algorithm="RS256",
        )
        with patch("app.PyJWKClient") as jwks_client:
            jwks_client.return_value.get_signing_key_from_jwt.return_value.key = (
                self.private_key.public_key()
            )
            with self.assertRaises(demo_app.HTTPException) as raised:
                demo_app.validate_id_token(
                    id_token,
                    "expected-nonce",
                    DISCOVERY["jwks_uri"],
                )
        self.assertEqual(raised.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
