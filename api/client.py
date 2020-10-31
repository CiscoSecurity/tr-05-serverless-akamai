from http import HTTPStatus
from urllib.parse import urljoin

import requests
from akamai.edgegrid import EdgeGridAuth
from requests.exceptions import SSLError, ConnectionError

from api.errors import (
    CriticalAkamaiResponseError,
    AuthorizationError,
    AkamaiSSLError,
    AkamaiConnectionError,
    AUTH_ERROR,
    INVALID_ARGUMENT
)


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

    def remove_from_network_list(self, network_list_id, observable_value):
        return self._modify_network_list(
            'DELETE', network_list_id, observable_value
        )

    def add_to_network_list(self, network_list_id, observable_value):
        return self._modify_network_list(
            'PUT', network_list_id, observable_value
        )

    def _modify_network_list(self, method, network_list_id, observable_value):
        return self._request(
            f'/network-list/v2/network-lists/{network_list_id}/elements',
            method=method,
            params={'element': observable_value}
        )

    def _request(self, path, method='GET', params=None):
        url = urljoin(f'https://{self.base_url}', path)
        expected_creds_errors = {
            HTTPStatus.UNAUTHORIZED: AUTH_ERROR,
            HTTPStatus.BAD_REQUEST: INVALID_ARGUMENT
        }

        try:
            response = self.session.request(
                method, url, headers=self.headers, params=params
            )
        except SSLError as error:
            raise AkamaiSSLError(error)
        except ConnectionError:
            raise AkamaiConnectionError(self.base_url)

        if response.status_code in expected_creds_errors:
            raise AuthorizationError(
                response.json().get('detail') or response.text,
                code=expected_creds_errors[response.status_code]
            )

        if response.ok:
            return response.json()

        raise CriticalAkamaiResponseError(response)
