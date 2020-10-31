from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests import Session, ConnectionError
from authlib.jose import jwt

from api.errors import AUTH_ERROR, INVALID_ARGUMENT, CONNECTION_ERROR
from .utils import headers


def routes():
    yield '/health'
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST{route}')
def route(request):
    return request.param


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode(
            'ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


@fixture(scope='session')
def wrong_jwt_structure():
    return 'wrong_jwt_structure'


@fixture(scope='session')
def wrong_payload_structure_jwt(client):
    header = {'alg': 'HS256'}

    payload = {
        'clientToken': 'xxx',
    }

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='module')
def authorization_errors_expected_payload(route: str):

    def _make_payload_message(message):
        payload = {
            'errors': [
                {
                    'code': AUTH_ERROR,
                    'message': f'Authorization failed: {message}',
                    'type': 'fatal'}
            ],
        }
        if route.endswith('/trigger'):
            payload.update({'data': {'status': 'failure'}})
        return payload

    return _make_payload_message


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):

    def _make_payload_message(code, message):
        payload = {
            'errors': [
                {
                    'code': code,
                    'message': f'{message}',
                    'type': 'fatal'
                }
            ],
        }
        if route.endswith('/trigger'):
            payload.update({'data': {'status': 'failure'}})
        return payload
    return _make_payload_message


def test_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_call_with_wrong_authorization_type(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt, auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_call_with_wrong_jwt_structure(
        route, client, wrong_jwt_structure, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(wrong_jwt_structure), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_call_with_jwt_encoded_by_wrong_key(
        route, client, invalid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(invalid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Failed to decode JWT with provided key'
    )


def test_call_with_wrong_jwt_payload_structure(
        route, client, wrong_payload_structure_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(wrong_payload_structure_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


def test_call_with_missed_secret_key(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    right_secret_key = client.application.secret_key
    client.application.secret_key = None
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    client.application.secret_key = right_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        '<SECRET_KEY> is missing'
    )


def test_call_with_unauthorized_access_token(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.UNAUTHORIZED, 'Invalid authorization access token'
        )

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: Invalid authorization access token'
        )


def test_call_with_unauthorized_client_token(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.BAD_REQUEST, 'Invalid authorization client token'
        )

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            INVALID_ARGUMENT,
            'Authorization failed: '
            'Invalid authorization client token'
        )


def test_call_with_unauthorized_signature(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.UNAUTHORIZED, 'The signature does not match'
        )

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json,
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: The signature does not match'
        )


def test_call_with_unauthorized_base_url(
        route, client, valid_jwt, valid_json,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = ConnectionError

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            CONNECTION_ERROR,
            'Authorization failed, validate the configured baseUrl: xxx'
        )
