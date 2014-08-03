import os
from pocket import Pocket
import analyzer

POCKET_CONSUMER_KEY = os.environ['POCKET_CONSUMER_KEY']
POCKET_ACCESS_TOKEN = os.environ.get('POCKET_ACCESS_TOKEN')

pocket_response = None # Store response contents

def get_pocket_items(access_token=None):
    if not access_token:
        access_token = get_pocket_access_token(POCKET_CONSUMER_KEY)
    pocket = Pocket(POCKET_CONSUMER_KEY, access_token)
    global pocket_response #jic you want to play with the data
    pocket_response = pocket.get(state='all')
    # Check out http://getpocket.com/developer/docs/v3/retrieve
    # for further filtering by API params
    return pocket_response[0]['list'].values() # No pagination, all items in list

def get_pocket_access_token(consumer_key):
    """Return access token needed to instantiate Pocket.

    You have to visit https://getpocket.com/auth/authorize
    to gain programatic access to the contents of your pocket account.

    Save token returned for future use.
    """
    request_token = Pocket.get_request_token(consumer_key=consumer_key)
    print 'Need to manually authorize code to make requests'
    r = input('Input "y" and press enter after inputing this url into your browser: https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=google.com' % request_token)
    # Visit to url authorizes request token to make other requests to user account
    return Pocket.get_access_token(consumer_key, request_token)
