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
import jinja2
import os
import time
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class User(db.Model):
    username = db.StringProperty(required=True)
    pocket_access_token = db.StringProperty(required=True)

    def save_bookmarks(self, offset=0):
        """Fetch items and store in db. 

        In order to do the pagination a recursion on the offset will 
        insert 1 items at a time on the database. 
        """
        new_bookmarks = []
        count = 1
        pocket_r = pocket_connect.get_pocket_items(self.pocket_access_token, state='all', detailType='complete', count=count, offset=offset)
        # Stop recursion if the items extracted is less than count.
        if len(pocket_r) < count or pocket_r == 'error':
            return
        for b in pocket_r:
            attrs = {
                    'user': self,
                    'title': b['resolved_title'],
                    'has_been_read': b['status'] == '1',
                    'is_favorite': b['favorite'] == '1',
                    'url': b['resolved_url'],
                    #'tags': str(b['tags'].keys()),
                    'excerpt': b['excerpt'],
                    'word_count': int(b['word_count'])
            }
            new_b = Bookmark(**attrs)
            new_b.put()
            new_bookmarks.append(new_b)
            #Function needed that shows the progress of the recursion to the user
            #show_progress_to_user()
        return self.save_bookmarks(offset+1)

class Bookmark(db.Model):
    user = db.ReferenceProperty(User, collection_name='bookmarks')
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
        request_token = pocket_connect.get_request_token()
        redirect_uri = 'http://localhost:14080/access?request_token=%s' % request_token
        self.redirect(str('https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s' % (request_token,redirect_uri)))

class AccessHandler(HelpHandler):
    def get(self):
        request_token = self.request.get('request_token')
        credentials = pocket_connect.get_credentials(request_token)
        user = User(username=credentials['username'], pocket_access_token=credentials['access_token'])
        user.put()
        user.save_bookmarks()
        self.response.headers.add_header('Set-Cookie', 'user_key='+str(user.key())+'; Path=/')
        self.redirect('/users')

class UsersHandler(HelpHandler):
    def get(self):
        user_key = self.request.cookies.get('user_key')
        user = User.get(user_key)
        self.render('user.html',user= user)

class BookmarkHandler(HelpHandler):
    def get(self):
        user_key = self.request.cookies.get('user_key')
        if not user_key:
            self.redirect('/')
        user = User.get(user_key)
        #fetch(None) returns all the entities of the query.
        user_bookmarks = user.bookmarks.fetch(None)
        self.render('bookmarks.html', bookmarks=user_bookmarks)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/access', AccessHandler),
    ('/users', UsersHandler),
    ('/bookmarks', BookmarkHandler)
], debug=True)
