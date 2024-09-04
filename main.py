import base64
import json
import requests
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class GovESB:
    def __init__(self):
        # Load environment variables from a .env file
        self.load_env()

        # Retrieve the necessary environment variables
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.client_id = os.getenv("CLIENT_ID")
        self.base_url = os.getenv("BASE_URL")
        self.base_auth_url = os.getenv("BASE_AUTH_URL")
        self.private_key_pem = os.getenv("PRIVATE_KEY_PEM").encode("utf-8")
        self.public_key_pem = os.getenv("PUBLIC_KEY_PEM").encode("utf-8")

    def load_env(self):
        """Load environment variables from a .env file."""
        load_dotenv()

    def get_token(self):
        """
        Obtain an access token from the authentication service using client credentials.

        Returns:
            str: Access token.
        """
        # Prepare the authorization header with base64 encoding
        authorization_token = f"{self.client_id}:{self.client_secret}"
        base64_authorization = base64.b64encode(
            authorization_token.encode("utf-8")
        ).decode("utf-8")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {base64_authorization}",
        }

        # Prepare the data for the token request
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        # Make the request to obtain the access token
        response = requests.post(f"{self.base_auth_url}", headers=headers, data=data)
        response_data = response.json()

        return response_data.get("access_token")

    def sign_data(self, data):
        """
        Sign the given data using the ECDSA private key.

        Args:
            data (dict): The data to be signed.

        Returns:
            str: The base64-encoded signature.
        """
        # Convert data to a JSON string with compact formatting
        data_json = json.dumps(data, separators=(",", ":"))

        # Load the PEM private key from the environment variable
        private_key = load_pem_private_key(self.private_key_pem, password=None)

        # Sign the data using ECDSA and SHA256
        signature = private_key.sign(
            data_json.encode("utf-8"), ec.ECDSA(hashes.SHA256())
        )

        # Return the base64-encoded signature
        return base64.b64encode(signature).decode("utf-8")

    def verify_signature(self, data, signature):
        """
        Verify the ECDSA signature of the given data.

        Args:
            data (dict): The data that was signed.
            signature (str): The base64-encoded signature to be verified.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        # Decode the base64-encoded signature
        signature_bytes = base64.b64decode(signature)

        # Load the PEM public key from the environment variable
        public_key = serialization.load_pem_public_key(self.public_key_pem)

        try:
            # Verify the signature using ECDSA and SHA256
            public_key.verify(
                signature_bytes,
                json.dumps(data, separators=(",", ":")).encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except Exception:
            return False

    def brela(self):
        """
        Example request to the BRELA API via the ESB, including data signing and signature verification.
        """
        # Prepare the data to be sent to BRELA
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

        # Sign the data
        signature = self.sign_data(data)

        # Prepare the payload to be sent
        data_to_send = json.dumps(
            {
                "data": data,
                "signature": signature,
            },
            separators=(",", ":"),
        )

        # Get the access token for authorization
        token = self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Send the request to the ESB
        response = requests.post(
            f"{self.base_url}/request", headers=headers, data=data_to_send
        )
        response_data = response.json()

        # Extract and verify the response data and signature
        r_data = response_data.get("data")
        r_signature = response_data.get("signature")
        is_verified = self.verify_signature(r_data, r_signature)
        print("BRELA Signature Verified:", is_verified)

    def necta(self):
        """
        Example request to the NECTA API via the ESB, including data signing and signature verification.
        """
        # Prepare the data to be sent to NECTA
        data = {
            "apiCode": "i82CGfWI",
            "esbBody": {
                "exam_year": 2023,
                "exam_id": 1,
                "index_number": "S3968-0035",
                "api_key": "$2y$10$V0Q9s.CWtGnRtPQRTVEP3OFv4.UUij4fyQMlRH7ON41Z5GRx5oOnS",
            },
        }

        # Sign the data
        signature = self.sign_data(data)

        # Prepare the payload to be sent
        data_to_send = json.dumps(
            {
                "data": data,
                "signature": signature,
            },
            separators=(",", ":"),
        )

        # Get the access token for authorization
        token = self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Send the request to the ESB
        response = requests.post(
            f"{self.base_url}/request", headers=headers, data=data_to_send
        )
        response_data = response.json()

        # Extract and verify the response data and signature
        r_data = response_data.get("data")
        r_signature = response_data.get("signature")
        is_verified = self.verify_signature(r_data, r_signature)
        print("NECTA Signature Verified:", is_verified)


# Example usage
gov_esb = GovESB()
# Uncomment to test BRELA API
# gov_esb.brela()
# Test NECTA API
gov_esb.necta()
