import socket
import validators

from helpers import common_strings

def validate_domain_or_ip(value):
    if not (validators.domain(value) or validators.ipv4(value)):
        return False
    else:
        return True

def resolve_domain_ip(data_input):
    return socket.gethostbyname(data_input)