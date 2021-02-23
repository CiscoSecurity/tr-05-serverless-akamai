from unittest.mock import call


def headers(jwt, auth_type='Bearer'):
    return {'Authorization': f'{auth_type} {jwt}'}


def check_akamai_request(
        request_mock, params, method='GET',
        uri='https://xxx/network-list/v2/network-lists'
):
    calls = [
        call.get(method='get',
                 url='https://visibility.amp.cisco.com/.well-known/jwks',
                 params=None, allow_redirects=True),
        call.get(method,
                 uri,
                 headers={
                     'Accept': 'application/json',
                     'User-Agent': 'SecureX Threat Response Integrations'
                                   ' <tr-integrations-support@cisco.com>'
                 },
                 params=params)

    ]
    request_mock.assert_has_calls(calls, any_order=False)
