import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    AKAMAI_OBSERVABLES = {
        'ip': 'IP',
        'ipv6': 'IPv6'
    }
