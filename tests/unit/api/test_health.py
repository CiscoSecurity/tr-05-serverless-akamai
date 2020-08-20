from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests import Session

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_without_jwt_failure(
        route, client, invalid_jwt_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_unauthorized_creds_failure(
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
        request_mock.assert_called_once_with(
            'GET', 'https://xxx/network-list/v2/network-lists',
            headers={'Accept': 'application/json',
                     'User-Agent': 'Cisco Threat Response Integrations'
                                   ' <tr-integrations-support@cisco.com>'},
            params={'listType': 'IP', 'includeElements': False}
        )


def test_health_call_success(route, client, valid_jwt, akamai_response_ok):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_ok
        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
        request_mock.assert_called_once_with(
            'GET', 'https://xxx/network-list/v2/network-lists',
            headers={'Accept': 'application/json',
                     'User-Agent': 'Cisco Threat Response Integrations'
                                   ' <tr-integrations-support@cisco.com>'},
            params={'listType': 'IP', 'includeElements': False}
        )
