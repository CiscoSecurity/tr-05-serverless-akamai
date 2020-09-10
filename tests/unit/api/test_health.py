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


def test_health_call_without_jwt(
        route, client, invalid_jwt_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_invalid_jwt(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


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
