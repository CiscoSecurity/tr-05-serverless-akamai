import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
