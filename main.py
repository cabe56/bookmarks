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
import json
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
    bookmark = Bookmark.get(bookmark_key)
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

    @staticmethod
    def favorites():
        return db.GqlQuery("SELECT * FROM Bookmark WHERE is_favorite=True").fetch(None)

    @staticmethod
    def user_favorites(user):
        return db.GqlQuery("SELECT * FROM Bookmark WHERE user=:u ORDER BY is_favorite DESC", u=user).fetch(None)

    @staticmethod
    def save_pocket_item(item, user):
        attrs = {
            'user': user,
            'title': item['resolved_title'],
            'has_been_read': item['status'] == '1',
            'is_favorite': item['favorite'] == '1',
            'url': item['resolved_url'],
            #'tags': str(item['tags'].keys()),
            'excerpt': item['excerpt'],
            'word_count': int(item['word_count'])
        }
        new_b = Bookmark(**attrs)
        new_b.put()
        return new_b

    @staticmethod
    def save_from_dump(user):
        items = pocket_connect.get_pocket_items_from_json()
        return map(lambda i: Bookmark.save_pocket_item(i, user), items)

class HelpHandler(webapp2.RequestHandler):
    def write (self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(HelpHandler):
    def get(self):
        user_key = self.request.cookies.get('user_key')
        user = get_by_key(user_key)
        if user:
            self.redirect('bookmarks')
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
        if user:
            self.render('user.html', user=user, bookmarks=Bookmark.user_favorites(user))
        else:
            self.redirect('/')

class BookmarkHandler(HelpHandler):
    def get(self):
        self.render('bookmarks.html', bookmarks=Bookmark.favorites())

class DumpHandler(HelpHandler):
    def get(self):
        user_key = self.request.cookies.get('user_key')
        user = get_by_key(user_key)
        if user and os.path.isfile('pocket_bookmarks.json.dump'):
            # If bookmark dump found, load into db
            Bookmark.save_from_dump(user)
        elif user:
            items = pocket_connect.get_pocket_items(
                    user.pocket_access_token, state='all',
                    detailType='complete')
            self.write(json.dumps(items))
        else:
            self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/bookmarks/dump', DumpHandler),
    ('/access', AccessHandler),
    ('/users', UsersHandler),
    ('/users/(.*)', UserPageHandler),
    ('/bookmarks', BookmarkHandler)
], debug=True)
