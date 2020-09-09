from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import PERMISSION_DENIED
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {
        'clientToken': 'xxx',
        'clientSecret': 'xxx',
        'accessToken': 'xxx',
        'baseUrl': 'xxx',
    }

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


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
def akamai_response_unauthorized_creds(secret_key):
    return akamai_api_response_mock(
        HTTPStatus.FORBIDDEN,
        json_=lambda: {'detail': 'Error: Bad API key'}
    )


@fixture(scope='session')
def akamai_response_ok(secret_key):
    return akamai_api_response_mock(
        HTTPStatus.OK,
        json_=lambda: 'OK'
    )


@fixture(scope='session')
def akamai_response_network_lists(secret_key):
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
def invalid_jwt_expected_payload(route):
    data = {}
    if route.endswith('/trigger'):
        data = {'status': 'failure'}

    return {
        'errors': [
            {
                'code': PERMISSION_DENIED,
                'message': 'Invalid Authorization Bearer JWT.',
                'type': 'fatal'}
        ],
        'data': data
    }


@fixture(scope='module')
def unauthorized_creds_expected_payload():
    return {
        'errors': [
            {
                'code': PERMISSION_DENIED,
                'message': 'Unexpected response from Akamai:'
                           ' Error: Bad API key',
                'type': 'fatal'
            }
        ],
        'data': {}
    }


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
