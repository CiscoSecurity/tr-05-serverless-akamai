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


def test_health_call_with_ssl_error(
        route, client, valid_jwt,
        sslerror_expected_payload,
        get_public_key
):
    with patch.object(Session, 'request') as request_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'

        request_mock.side_effect = (get_public_key, SSLError(mock_exception))

        response = client.post(
            route, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_health_call_success(route, client, valid_jwt,
                             akamai_response_ok, get_public_key):
    with patch.object(Session, 'request') as request_mock:
        request_mock.side_effect = (get_public_key, akamai_response_ok)

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
        check_akamai_request(
            request_mock, {'listType': 'IP', 'includeElements': False}
        )
