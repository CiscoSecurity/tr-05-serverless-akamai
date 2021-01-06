def headers(jwt, auth_type='Bearer'):
    return {'Authorization': f'{auth_type} {jwt}'}


def check_akamai_request(
        request_mock, params, method='GET',
        uri='https://xxx/network-list/v2/network-lists'
):
    request_mock.assert_called_once_with(
        method,
        uri,
        headers={'Accept': 'application/json',
                 'User-Agent': 'SecureX Threat Response Integrations'
                               ' <tr-integrations-support@cisco.com>'},
        params=params
    )
