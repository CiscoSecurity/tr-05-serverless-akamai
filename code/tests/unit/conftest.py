from tests.utils.crypto import generate_rsa_key_pair
import jwt
from http import HTTPStatus
from pytest import fixture
from unittest.mock import MagicMock

from api.errors import UNKNOWN
from api.respond import ADD_ACTION_ID
from app import app


@fixture(scope="session")
def test_keys_and_token():
    private_pem, jwks, kid = generate_rsa_key_pair()
    wrong_private_pem, wrong_jwks, _ = generate_rsa_key_pair()

    return {
        "private_key": private_pem,
        "jwks": jwks,
        "kid": kid,
        "wrong_private_key": wrong_private_pem,
        "wrong_jwks": wrong_jwks,
    }


@fixture(scope='session')
def client(test_keys_and_token):
    app.rsa_private_key = test_keys_and_token["private_key"]

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            missing_jwks_host=False
    ):
        payload = {
            'clientToken': 'xxx',
            'clientSecret': 'xxx',
            'accessToken': 'xxx',
            'baseUrl': 'xxx',
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('clientToken')
        if missing_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def valid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'ip', 'value': '1.1.1.1'}]

    if route.endswith('/trigger'):
        return {'action-id': ADD_ACTION_ID,
                'observable_type': 'ip',
                'observable_value': '1.1.1.1',
                'network_list_id': 'nli'}


@fixture(scope='session')
def akamai_call_headers():
    return {
        'Accept': 'application/json',
        'User-Agent': 'Cisco Threat Response Integrations'
                      ' <tr-integrations-support@cisco.com>'
    }


def akamai_api_response_mock(status_code, text=None, json_=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json = json_

    return mock_response


@fixture(scope='session')
def akamai_response_unauthorized_creds():
    def _make_response(code, message):
        return akamai_api_response_mock(
            code,
            json_=lambda: {'detail': f'{message}'}
        )
    return _make_response


@fixture(scope='session')
def akamai_response_ok():
    return akamai_api_response_mock(
        HTTPStatus.OK,
        json_=lambda: 'OK'
    )


@fixture(scope='session')
def get_public_key(test_keys_and_token):
    mock_response = MagicMock()
    payload = test_keys_and_token["jwks"]
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def get_wrong_public_key(test_keys_and_token):
    mock_response = MagicMock()
    payload = test_keys_and_token["wrong_jwks"]
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def akamai_response_network_lists():
    return akamai_api_response_mock(
        HTTPStatus.OK,
        json_=lambda: {
            'links': [],
            'networkLists': [
                {
                    'readOnly': True,
                    'uniqueId': 'A',
                    'name': 'A',
                    'list': []
                },
                {
                    'readOnly': False,
                    'uniqueId': 'B',
                    'name': 'B',
                    'list': ['1.1.1.1']
                },
                {
                    'uniqueId': 'C',
                    'name': 'C',
                    'list': ['2.2.2.2']
                },
                {
                    'uniqueId': 'D',
                    'name': 'D',
                    'list': ['2.2.2.2']
                },
                {
                    'uniqueId': 'F',
                    'name': 'F',
                    'list': ['1.1.1.1']
                }
            ]
        }
    )


@fixture(scope='module')
def sslerror_expected_payload(route):
    payload = {
        'errors': [
            {
                'code': UNKNOWN,
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }
    if route.endswith('/trigger'):
        payload.update({'data': {'status': 'failure'}})
    return payload


@fixture(scope='module')
def respond_observables_expected_payload():
    return {
        "data": [
            {
                "categories": [
                    "Akamai"
                ],
                "description": "Add IP to Network List",
                "id": "akamai-add-to-network-list",
                "query-params": {
                    "network_list_id": "C",
                    "observable_type": "ip",
                    "observable_value": "1.1.1.1"
                },
                "title": "Add to C"
            },
            {
                "categories": [
                    "Akamai"
                ],
                "description": "Add IP to Network List",
                "id": "akamai-add-to-network-list",
                "query-params": {
                    "network_list_id": "D",
                    "observable_type": "ip",
                    "observable_value": "1.1.1.1"
                },
                "title": "Add to D"
            },
            {
                "categories": [
                    "Akamai"
                ],
                "description": "Remove IP from Network List",
                "id": "akamai-remove-from-network-list",
                "query-params": {
                    "network_list_id": "B",
                    "observable_type": "ip",
                    "observable_value": "1.1.1.1"
                },
                "title": "Remove from B"
            },
            {
                "categories": [
                    "Akamai"
                ],
                "description": "Remove IP from Network List",
                "id": "akamai-remove-from-network-list",
                "query-params": {
                    "network_list_id": "F",
                    "observable_type": "ip",
                    "observable_value": "1.1.1.1"
                },
                "title": "Remove from F"
            }
        ]
    }
