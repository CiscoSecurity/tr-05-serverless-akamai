from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests import Session
from requests.exceptions import SSLError

from .utils import headers, check_akamai_request


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


def test_health_call_with_unauthorized_creds(
        route, client, valid_jwt,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload
        check_akamai_request(
            request_mock, {'listType': 'IP', 'includeElements': False}
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
