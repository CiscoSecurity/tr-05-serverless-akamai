import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    AKAMAI_OBSERVABLES = {
        'ip': 'IP',
        'ipv6': 'IPv6'
    }
