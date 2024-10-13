from abc import ABC, abstractclassmethod
from typing import Union, Literal
import hmac
import hashlib
import requests
from urllib.parse import urlencode
import logging
import time

logger = logging.getLogger(__name__)

class MexcAPIError(Exception): 
    pass

class MexcSDK(ABC):
    """
    Initializes a new instance of the class with the given `api_key` and `api_secret` parameters.

    :param api_key: A string representing the API key.
    :param api_secret: A string representing the API secret.
    :param base_url: A string representing the base URL of the API.
    """
    def __init__(self, api_key: str, api_secret: str, base_url: str, proxies: dict = None):
        self.api_key = api_key
        self.api_secret = api_secret

        self.recvWindow = 5000

        self.base_url = base_url

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
        })

        if proxies:
            self.session.proxies.update(proxies)


    @abstractclassmethod
    def sign(self, **kwargs) -> str:
        ...
    
    @abstractclassmethod
    def call(self, method: Union[Literal["GET"], Literal["POST"], Literal["PUT"], Literal["DELETE"]], router: str, *args, **kwargs) -> dict:
        ...

class _SpotHTTP(MexcSDK):
    def __init__(self, api_key: str = None, api_secret: str = None, proxies: dict = None):
        super().__init__(api_key, api_secret, "https://api.mexc.com", proxies = proxies)

        self.session.headers.update({
            "X-MEXC-APIKEY": self.api_key
        })

    def sign(self, query_string: str) -> str:
        """
        Generates a signature for an API request using HMAC SHA256 encryption.

        Args:
            **kwargs: Arbitrary keyword arguments representing request parameters.

        Returns:
            A hexadecimal string representing the signature of the request.
        """
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

    def call(self, method: Union[Literal["GET"], Literal["POST"], Literal["PUT"], Literal["DELETE"]], router: str, auth: bool = True, *args, **kwargs) -> dict:
        if not router.startswith("/"):
            router = f"/{router}"

        # clear None values
        kwargs = {k: v for k, v in kwargs.items() if v is not None}

        if kwargs.get('params'):
            kwargs['params'] = {k: v for k, v in kwargs['params'].items() if v is not None}
        else:
            kwargs['params'] = {}

        timestamp = str(int(time.time() * 1000))
        kwargs['params']['timestamp'] = timestamp
        kwargs['params']['recvWindow'] = self.recvWindow

        kwargs['params'] = dict(sorted(kwargs['params'].items()))
        params = urlencode(kwargs.pop('params'), doseq=True).replace('+', '%20')

        if self.api_key and self.api_secret and auth:
            params += f"&signature={self.sign(params)}"


        response = self.session.request(method, f"{self.base_url}{router}", params = params, *args, **kwargs)

        if not response.ok:
            raise MexcAPIError(f'(code={response.json()["code"]}): {response.json()["msg"]}')

        return response.json()
    
class _FuturesHTTP:
    def __init__(self, api_key: str, api_secret: str, proxies: dict = None):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://contract.mexc.com"
        self.recvWindow = 5000  # 5 seconds allowed for timestamp drift

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "ApiKey": self.api_key  # Correctly set the API Key header
        })

        if proxies:
            self.session.proxies.update(proxies)

    def sign(self, timestamp: str, params: dict) -> str:
        """
        Generate HMAC SHA256 signature.
        The signature string includes API key, timestamp, and sorted query string.
        """
        query_string = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
        message = f"{self.api_key}{timestamp}{query_string}"
        return hmac.new(
            self.api_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

    def call(self, method: Union[Literal["GET"], Literal["POST"]], router: str, **kwargs) -> dict:
        """
        Make an authenticated API request to MEXC Futures.
        """
        if not router.startswith("/"):
            router = f"/{router}"

        params = kwargs.get("params", {})
        params["timestamp"] = str(int(time.time() * 1000))  # Add timestamp
        params["recvWindow"] = self.recvWindow  # Add recvWindow

        # Sort and encode query string
        encoded_params = urlencode(params, doseq=True)

        # Generate signature
        signature = self.sign(params["timestamp"], params)

        # Add signature to headers
        headers = {
            "Request-Time": params["timestamp"],
            "Signature": signature,
        }
        headers |= self.session.headers

        # Make the request
        url = f"{self.base_url}{router}"
        response = self.session.request(method, url, headers=headers, params=encoded_params)

        # Handle potential errors
        if not response.ok:
            raise MexcAPIError(f"(code={response.status_code}): {response.text}")

        return response.json()
