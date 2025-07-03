from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests import Session
from requests.exceptions import InvalidURL, ConnectionError
from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWKS_HOST,
    WRONG_PAYLOAD_STRUCTURE,
    JWKS_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)
from api.errors import AUTH_ERROR, INVALID_ARGUMENT, CONNECTION_ERROR
from .utils import headers


def routes():
    yield '/health'
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST{route}')
def route(request):
    return request.param


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
        NO_AUTH_HEADER
    )


def test_call_with_wrong_authorization_type(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(), auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE
    )


def test_call_with_wrong_jwt_structure(
        route, client, valid_json,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = get_public_key
        response = client.post(
            route, headers=headers('this_is_not_a_jwt'), json=valid_json
        )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


def test_call_with_wrong_kid(
        route, client, valid_json,
        authorization_errors_expected_payload,
        get_public_key, valid_jwt
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = get_public_key
        response = client.post(
            route, headers=headers(valid_jwt(kid='wrong_kid')), json=valid_json
        )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
       KID_NOT_FOUND
    )


def test_call_with_wrong_jwks_host(
    route, client, valid_json, valid_jwt,
    authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        with patch.object(Session, 'request') as request_mock:
            request_mock.side_effect = error()

            response = client.post(
                route, json=valid_json, headers=headers(valid_jwt())
            )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


def test_call_with_wrong_jwt_payload_structure(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = get_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt(wrong_structure=True))
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE)


def test_call_without_jwks_host(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = get_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(missing_jwks_host=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING)


def test_call_with_unauthorized_access_token(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = (
            get_public_key,
            akamai_response_unauthorized_creds(
                HTTPStatus.UNAUTHORIZED,
                'Invalid authorization access token'
            )
        )

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
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
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = (
            get_public_key,
            akamai_response_unauthorized_creds(
                HTTPStatus.BAD_REQUEST,
                'Invalid authorization client token')
        )

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            INVALID_ARGUMENT,
            'Unexpected response from Akamai: '
            'Invalid authorization client token'
        )


def test_call_with_unauthorized_signature(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = (
            get_public_key,
            akamai_response_unauthorized_creds(
                HTTPStatus.UNAUTHORIZED, 'The signature does not match'
            )
        )

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json,
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: The signature does not match'
        )


def test_call_with_unauthorized_base_url(
        route, client, valid_jwt, valid_json,
        unauthorized_creds_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = (get_public_key, ConnectionError)

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            CONNECTION_ERROR,
            'Unable to connect Akamai, validate the configured baseUrl: xxx'
        )


def test_call_with_wrong_audience(
        route, client, valid_json, valid_jwt, get_public_key,
        authorization_errors_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = get_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt(aud='wrong_aud'))
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


def test_call_with_wrong_public_key(
        route, client, valid_json, valid_jwt, get_wrong_public_key,
        authorization_errors_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = get_wrong_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt())
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )
