import json

# Every failure a client can meet, by a stable code. Code, CLI and any visual
# interface decide by the code and may translate it; the text is a default.
MESSAGES = {
    # Registration.
    'registration_closed': 'Registration is closed on this server',
    'invalid_username': 'The username needs 3 to 32 letters, digits, dots, dashes or underscores',
    'invalid_email': 'The email is not valid',
    'passwords_differ': 'The passwords do not match',
    'invalid_account': 'Invalid account details',
    'username_taken': 'The username is taken',
    'email_taken': 'The email is taken',
    'too_many_registrations': 'Too many new accounts from this address',
    # Login.
    'incorrect_credentials': 'Incorrect credentials',
    'too_many_attempts': 'Too many attempts: wait {wait} seconds',
    'invalid_server': 'The server could not prove the password',
    'not_authenticated': 'Log in before this action',
    'server_unreachable': 'The server did not answer',
    # After login.
    'no_networks': 'The account has no networks: create an organization or wait to be added to one',
    'network_unavailable': 'The network is not available',
    'network_conflict': 'The network cannot be used with the others of this account',
    'account_blocked': 'The account is blocked in this organization',
    'account_missing': 'The account does not exist',
    'invalid_name': 'The name needs 1 to 40 characters',
    'organization_limit': 'An account may administer at most {limit} organizations',
    'network_lost': 'The selected network is no longer available',
    'session_ended': 'An administrator ended this session',
    'unknown_action': 'Unknown control action',
    'tun_missing': 'A TUN driver is required to connect the VPN client',
}


def describe(code: str, **details) -> dict:
    # What the server sends: the code, the default text and any numbers in it.
    message = MESSAGES.get(code, code)
    try: message = message.format(**details)
    except (KeyError, IndexError): pass
    return dict(details, error=code, message=message)


class VPNError(Exception):
    """A failure the person can act on, with the server's code and details."""

    def __init__(self, code: str, message: str = None, **details):
        self.code, self.details = code, details
        self.message = message or describe(code, **details)['message']
        super().__init__(self.message)

    @classmethod
    def from_reply(cls, reply: dict) -> 'VPNError':
        details = {key: value for key, value in reply.items() if key not in ('error', 'message', 'request')}
        return cls(str(reply.get('error')), reply.get('message'), **details)

    @classmethod
    def from_bytes(cls, content: bytes) -> 'VPNError':
        try: reply = json.loads(content)
        except (UnicodeDecodeError, ValueError): reply = None
        if type(reply) is not dict or type(reply.get('error')) is not str: return cls('invalid_server')
        return cls.from_reply(reply)


def encode(code: str, **details) -> bytes:
    return json.dumps(describe(code, **details), separators=(',', ':')).encode()
