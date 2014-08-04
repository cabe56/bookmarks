import os
from vendor.pocket import Pocket
import analyzer

CONSUMER_KEY = '30573-f8d6198585aa28b9389b5956' # Pocket Stats app

def get_pocket_items(access_token, **params):
    pocket = Pocket(CONSUMER_KEY, access_token)
    pocket_response = pocket.get(**params)
    # Check out http://getpocket.com/developer/docs/v3/retrieve
    # for further filtering by API params
    return pocket_response[0]['list'].values() # No pagination, all items in list

def get_request_token():
    """Return request token needed to obtain access token for Pocket."""
    return Pocket.get_request_token(consumer_key=CONSUMER_KEY)

def get_credentials(request_token):
    """Return token needed to make authenticated requests and username of the user."""
    return  Pocket.get_credentials(CONSUMER_KEY, request_token)

def get_access_token(request_token):
    """Return token needed to make authenticated requests."""
    return Pocket.get_access_token(CONSUMER_KEY, request_token)
