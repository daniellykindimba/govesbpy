from regex import B
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import json
import requests
import hashlib
import os


class GovESB:
    def __init__(self):
        # Load environment variables
        self.load_env()

        self.client_secret = os.getenv("CLIENT_SECRET")
        self.client_id = os.getenv("CLIENT_ID")
        self.base_url = os.getenv("BASE_URL")
        self.base_auth_url = os.getenv("BASE_AUTH_URL")
        self.private_key_pem = os.getenv("PRIVATE_KEY_PEM").encode("utf-8")
        self.public_key_pem = os.getenv("PUBLIC_KEY_PEM").encode("utf-8")

    def load_env(self):
        from dotenv import load_dotenv

        load_dotenv()

    def get_token(self):
        authorization_token = f"{self.client_id}:{self.client_secret}"
        authorization_token_bytes = authorization_token.encode("utf-8")
        base64_bytes = base64.b64encode(authorization_token_bytes)
        base64_authorization = base64_bytes.decode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {base64_authorization}",
        }
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }
        response = requests.post(f"{self.base_auth_url}", headers=headers, data=data)
        response_data = json.loads(response.content)
        return response_data.get("access_token")

    def signdata(self, data):
        data_json = json.dumps(data, separators=(",", ":"))

        # Load the PEM private key
        private_key = load_pem_private_key(self.private_key_pem, password=None)

        # Sign the data
        signature = private_key.sign(
            str(data_json).encode("ascii"), ec.ECDSA(hashes.SHA256())
        )

        return base64.b64encode(signature).decode("ascii")

    def verify_signature(self, data, signature):
        # Decode the base64-encoded signature
        signature_bytes = base64.b64decode(signature)

        public_key = serialization.load_pem_public_key(self.public_key_pem)

        # Verify the signature
        try:
            verified = public_key.verify(
                signature_bytes, str(data).encode("ascii"), ec.ECDSA(hashes.SHA256())
            )
            if not verified:
                return True
            return False
        except Exception as e:
            print("Error verifying signature: ", e)
            return

    def brela(self):
        data = {
            "apiCode": "6hFRR5ro",
            "esbBody": {
                "requestdata": {
                    "RegistrationNumber": "159314480",
                    "ApiKey": "TEST-400c0a84-da97-46a8-b93cbca",
                    "EntityType": 1,
                }
            },
        }
        data_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        print("data bytes: ", data_bytes)

        signature = self.signdata(data)
        print("====signature: ", signature)

        data_to_send = {
            "data": data,
            "signature": signature,
        }
        print("data_to_send", json.dumps(data_to_send, separators=(",", ":")))
        data_to_send = json.dumps(data_to_send, separators=(",", ":"))

        token = self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        print("headers==", headers)

        response = requests.post(
            f"{self.base_url}/request", headers=headers, data=data_to_send
        )
        print("Response: ", response.content)
        response_data = json.loads(response.content)
        r_data = response_data.get("data")
        r_signature = response_data.get("signature")
        print("Response Data: ", r_data)
        print("Response Signature: ", r_signature)
        # verify signature
        is_verified = self.verify_signature(
            json.dumps(r_data, separators=(",", ":")), r_signature
        )
        print("is_verified: ", is_verified)

    def necta(self):
        data = {
            "apiCode": "i82CGfWI",
            "esbBody": {
                "exam_year": 2023,
                "exam_id": 1,
                "index_number": "S3968-0035",
                "api_key": "$2y$10$V0Q9s.CWtGnRtPQRTVEP3OFv4.UUij4fyQMlRH7ON41Z5GRx5oOnS",
            },
        }
        data_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        print("data bytes: ", data_bytes)

        signature = self.signdata(data)
        print("====signature: ", signature)

        data_to_send = {
            "data": data,
            "signature": signature,
        }
        print("data_to_send", json.dumps(data_to_send, separators=(",", ":")))
        data_to_send = json.dumps(data_to_send, separators=(",", ":"))

        token = self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        print("headers==", headers)

        response = requests.post(
            f"{self.base_url}/request", headers=headers, data=data_to_send
        )
        print("Response: ", response.content)
        response_data = json.loads(response.content)
        r_data = response_data.get("data")
        r_signature = response_data.get("signature")
        print("Response Data: ", r_data)
        print("Response Signature: ", r_signature)
        # verify signature
        is_verified = self.verify_signature(
            json.dumps(r_data, separators=(",", ":")), r_signature
        )
        print("is_verified: ", is_verified)


# Example usage
gov_esb = GovESB()
# gov_esb.brela()
gov_esb.necta()
