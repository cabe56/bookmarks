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
    total_pocket_items = db.IntegerProperty()
    last_access_to_pocket = db.IntegerProperty()


    def fetch_bookmarks(self, offset=0, count=1):
        """Fetch items and store in db. Return total number of inserted bookmarks.

        In order to do the pagination a recursion on the offset will 
        insert "count" items at a time on the database. 
        """
        response_items = pocket_connect.get_pocket_items(self.pocket_access_token, state='all', detailType='complete', count=count, offset=offset, since=self.last_access_to_pocket)
        # Stop recursion if the items extracted is less than count.
        if len(response_items) < count or response_items == []:
            #return total number of items extracted and update last_access_to_pocket
            self.last_access_to_pocket = int(time.time())
            return offset + len(response_items)
        self.save_bookmarks(response_items)
        #show_progress_to_user()    
        return self.fetch_bookmarks(offset+count)
    def save_bookmarks(self, bookmarks):
        for bookmark in bookmarks:
            attrs = {
                    'user': self,
                    'title': bookmark['resolved_title'],
                    'has_been_read': bookmark['status'] == '1',
                    'is_favorite': bookmark['favorite'] == '1',
                    'url': bookmark['resolved_url'],
                    #'tags': str(bookmark['tags'].keys()),
                    'excerpt': bookmark['excerpt'],
                    'word_count': int(bookmark['word_count'])
            }
            new_b = Bookmark(**attrs)
            new_b.put()
        return
            

class Bookmark(db.Model):
    user = db.ReferenceProperty(User)
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
        self.render('home.html')
        return
        request_token = pocket_connect.get_request_token()
        redirect_uri = 'http://localhost:14080/access?request_token=%s' % request_token
        self.redirect(str('https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s' % (request_token,redirect_uri)))

class AccessHandler(HelpHandler):
    def get(self):
        #If user is already in db, no need to get autorization from Pocket.
        user_key = self.request.cookies.get('user_key')
        user = User.get(user_key)
        if not user:
            request_token = self.request.get('request_token')
            credentials = pocket_connect.get_credentials(request_token)
            user = User(username=credentials['username'], pocket_access_token=credentials['access_token'], last_access_to_pocket=0)
            user.put()
        total_items_extracted = user.fetch_bookmarks()
        #If user had already extracted items from pocket, we add the amount of new ones.
        if user.total_pocket_items != None:     
            user.total_pocket_items += total_items_extracted
        else:
            user.total_pocket_items = total_items_extracted
        user.put()
        self.response.headers.add_header('Set-Cookie', 'user_key='+str(user.key())+'; Path=/')
        self.redirect('/users')

class UsersHandler(HelpHandler):
    def get(self):
        users = User.all().fetch(None)
        self.render('users.html',users= users)
    def post(self):
        email = self.request.get('email')
        self.response.write(email)

class UserPageHandler(HelpHandler):
    def get(self, user_key):
        #Check if user_key points to a user in the db; if not, redirect him to home page.
        try:
            user = User.get(user_key)
        except:
            self.redirect('/')
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
