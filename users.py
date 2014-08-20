import re
import hashlib
import random
import string
import time
import main
import pocket_connect
from google.appengine.ext import db

#Regular Expressions used in validation functions.
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#Functions used to validate input in signup form.
def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

#Functions used to encrypt passwords
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt =''):
    if salt == '':
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    if h == make_pw_hash(name,pw,salt):
        return True
    else:
        return False

def login_signup_logic(self, email, password):
    valid_e = valid_email(email)
    valid_pass = valid_password(password)
    error = ''
    if valid_pass and valid_e:
        user_query = db.GqlQuery(" SELECT * FROM User WHERE email=:email", email = email)
        user = user_query.get()
        if user == None:
            #If everything in the signup form is valid, get authorization from pocket.
            self.response.headers.add_header('Set-Cookie', 'email=%s; Path=/' % str(email))
            self.response.headers.add_header('Set-Cookie', 'user_pass=%s; Path=/' % str(password))
            request_token = pocket_connect.get_request_token()
            redirect_uri = 'http://localhost:14080/access?request_token=%s' % request_token
            self.redirect(str('https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s' % (request_token,redirect_uri)))
        else:
            if valid_pw(email, password, user.password):
                user_key = user.key()
                self.response.headers.add_header('Set-Cookie', 'user_key='+str(user_key)+'; Path=/')
                self.redirect('/bookmarks')
            else:
                error = "An account with that email already exists (and that is not the correct password)."
    if not valid_pass:
        error = 'Please enter a valid password.'
    if not valid_e:
        error = 'Please enter a valid email address.'
    return error

class User(db.Model):
    email = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    pocket_access_token = db.StringProperty(required=True)
    total_pocket_items = db.IntegerProperty()
    last_access_to_pocket = db.IntegerProperty()

    @property
    def fav_count(self):
        # Return number of favorited bookmarks
        return main.Bookmark.favorites_count(self)

    @property
    def bookmark_count(self):
        # Return number of total bookmarks
        return self.bookmark_set.count()

    @property
    def bookmark_list_desc(self):
        return "%i favs out of %i" % (self.fav_count, self.bookmark_count)

    def record_pocket_access(self):
        """Save timestamp to indicate access to pocket."""
        self.last_access_to_pocket = int(time.time())

    def fetch_bookmarks(self, offset=0, count=1):
        """Fetch items and store in db. Return total number of inserted bookmarks.

        In order to do the pagination a recursion on the offset will
        insert "count" items at a time on the database.
        """
        response_items = pocket_connect.get_pocket_items(self.pocket_access_token, state='all', detailType='complete', count=count, offset=offset, since=self.last_access_to_pocket)
        # Stop recursion if the items extracted is less than count.
        if len(response_items) < count or response_items == []:
            #return total number of items extracted and update last_access_to_pocket
            self.record_pocket_access()
            return offset + len(response_items)
        for item in response_items:
            main.Bookmark.save_pocket_item(item, self)
        #show_progress_to_user()
        return self.fetch_bookmarks(offset+count)
