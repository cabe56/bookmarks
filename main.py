#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import pocket_connect
import analyzer
import users
import jinja2
import os
import time
import users
from google.appengine.ext import db
from google.appengine.api import taskqueue

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#Gets user with a specific key, if error, returns None.
def get_by_key(key):
    try:
        return users.User.get(key)
    except:
        return None

def get_bookmark(key):
    bookmark_key = db.Key.from_path('Bookmark', str(key))
    bookmark =Bookmark.get(bookmark_key)
    return bookmark
    
class Bookmark(db.Model):
    user = db.ReferenceProperty(users.User)
    url = db.StringProperty(required=True)
    title = db.StringProperty()
    has_been_read = db.BooleanProperty()
    is_favorite = db.BooleanProperty()
    excerpt = db.TextProperty()
    tags = db.TextProperty()
    word_count = db.IntegerProperty()

class HelpHandler(webapp2.RequestHandler):
    def write (self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self,template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(HelpHandler):
    def get(self):
        user_key = self.request.cookies.get('user_key')
        user = get_by_key(user_key)
        if user:
            self.redirect('/bookmarks') 
        else:
            self.render('home.html')        

class AccessHandler(HelpHandler):
    def get(self):
        #If user is already in db, no need to get autorization from Pocket.
        user_key = self.request.cookies.get('user_key')
        user = get_by_key(user_key)
        if not user:
            email = self.request.cookies.get('email')
            user_pass = self.request.cookies.get('user_pass')
            request_token = self.request.get('request_token')
            credentials = pocket_connect.get_credentials(request_token)
            user = users.User(email=email, password=users.make_pw_hash(email,user_pass), pocket_access_token=credentials['access_token'], last_access_to_pocket=0)
            user.put()
        #Erase password cookie.
        self.response.headers.add_header('Set-Cookie', 'user_pass=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user_key='+str(user.key())+'; Path=/')
        taskqueue.add(url='/access', params={'user_key':user.key()})
        self.redirect('/bookmarks')

    #Posts send to '/access' are tasks for fetching user's bookmark
    def post(self):
        user_key = str(self.request.get('user_key'))
        user = get_by_key(user_key)
        total_items_extracted = user.fetch_bookmarks()
        #If user had already extracted items from pocket, we add the amount of new ones.
        if user.total_pocket_items != None:     
            user.total_pocket_items += total_items_extracted
        else:
            user.total_pocket_items = total_items_extracted
        user.put()

class UsersHandler(HelpHandler):
    def get(self):
        users_names = users.User.all().fetch(None)
        self.render('users.html', users=users_names)

    def post(self):
        email = self.request.get('email')
        password = self.request.get('password')
        error = users.login_signup_logic(self,email,password)
        self.render('home.html', email=email, error=error)

class UserPageHandler(HelpHandler):
    def get(self, user_key):
        #Check if user_key points to a user in the db; if not, redirect him to home page.
        user = get_by_key(user_key)
        if not user:
            self.redirect('/')
            return
        user_bookmarks = user.bookmark_set.fetch(None)
        self.render('user.html', user=user, bookmarks=user_bookmarks)

class BookmarkHandler(HelpHandler):
    def get(self):
        bookmarks = db.GqlQuery(" SELECT * FROM Bookmark WHERE is_favorite=True ").fetch(None)
        self.render('bookmarks.html', bookmarks=bookmarks)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/access', AccessHandler),
    ('/users', UsersHandler),
    ('/users/(.*)', UserPageHandler),
    ('/bookmarks', BookmarkHandler)
], debug=True)
