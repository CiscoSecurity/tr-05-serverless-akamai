from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests import Session
from requests.exceptions import SSLError, ConnectionError

from .utils import headers, check_akamai_request
from api.errors import INVALID_ARGUMENT, AUTH_ERROR


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_authorization_header_failure(
        route, client,
        authorization_errors_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_health_call_with_wrong_authorization_type(
        route, client, valid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(valid_jwt, auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_health_call_with_wrong_jwt_structure(
        route, client, wrong_jwt_structure,
        authorization_errors_expected_payload
):
    response = client.post(route, headers=headers(wrong_jwt_structure))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_health_call_with_jwt_encoded_by_wrong_key(
        route, client, invalid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Failed to decode JWT with provided key'
    )


def test_health_call_with_wrong_jwt_payload_structure(
        route, client, wrong_payload_structure_jwt,
        authorization_errors_expected_payload
):
    response = client.post(route,
                           headers=headers(wrong_payload_structure_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


def test_health_call_with_missed_secret_key(
        route, client, valid_jwt,
        authorization_errors_expected_payload
):
    right_secret_key = client.application.secret_key
    client.application.secret_key = None
    response = client.post(route, headers=headers(valid_jwt))
    client.application.secret_key = right_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        '<SECRET_KEY> is missing'
    )


def test_health_call_with_unauthorized_access_token(
        route, client, valid_jwt,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.UNAUTHORIZED, 'Invalid authorization access token'
        )

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: Invalid authorization access token'
        )


def test_health_call_with_unauthorized_client_token(
        route, client, valid_jwt,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.BAD_REQUEST, 'Invalid authorization client token'
        )

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            INVALID_ARGUMENT,
            'Unexpected response from Akamai: '
            'Invalid authorization client token'
        )


def test_health_call_with_unauthorized_signature(
        route, client, valid_jwt,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds(
            HTTPStatus.UNAUTHORIZED, 'The signature does not match'
        )

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: The signature does not match'
        )


def test_health_call_with_unauthorized_base_url(
        route, client, valid_jwt,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = ConnectionError

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload(
            AUTH_ERROR,
            'Authorization failed: Unable to connect Akamai, '
            'validate the configured baseUrl: xxx'
        )


def test_health_call_with_ssl_error(
        route, client, valid_jwt,
        sslerror_expected_payload
):
    with patch.object(Session, 'request') as request_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        request_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_health_call_success(route, client, valid_jwt, akamai_response_ok):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_ok

        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
        check_akamai_request(
            request_mock, {'listType': 'IP', 'includeElements': False}
        )
