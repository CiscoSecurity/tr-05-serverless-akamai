from http import HTTPStatus
from urllib.parse import urljoin, urlencode

import requests
from akamai.edgegrid import EdgeGridAuth

from api.errors import (
    CriticalAkamaiResponseError

)

NOT_CRITICAL_ERRORS = (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND)


class AkamaiClient:
    def __init__(self, credentials, user_agent):
        self.base_url = credentials['baseUrl']
        self.headers = {
            'Accept': 'application/json',
            'User-Agent': user_agent
        }

        self.session = requests.Session()
        self.session.auth = EdgeGridAuth(
            client_token=credentials['clientToken'],
            client_secret=credentials['clientSecret'],
            access_token=credentials['accessToken']
        )

    def network_lists(self, include_elements=True):
        params = {'listType': 'IP', 'includeElements': include_elements}
        return self._request('/network-list/v2/network-lists', params=params)

    def _request(self, path, method='GET', params=None):
        url = urljoin(f'https://{self.base_url}', path)

        response = self.session.request(
            method, url, headers=self.headers, params=params
        )

        if response.ok:
            return response.json()

        if response.status_code in NOT_CRITICAL_ERRORS:
            return {}

        raise CriticalAkamaiResponseError(response)
