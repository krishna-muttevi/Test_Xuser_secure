import requests


class RequestClient:


    DEFAULT_TIMEOUT = 10  # seconds

    def __init__(self, auth=None, headers=None):
        self.session = requests.Session()
        self.auth = auth
        self.headers = headers or {}

    def _request(self, method, url, **kwargs):
        try:
            response = self.session.request(
                method=method,
                url=url,
                auth=kwargs.pop("auth", self.auth),
                headers=kwargs.pop("headers", self.headers),
                timeout=self.DEFAULT_TIMEOUT,
                **kwargs
            )
            return response

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"HTTP request failed: {str(e)}")

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self._request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._request("DELETE", url, **kwargs)