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
from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required=True)
    pocket_access_token = db.StringProperty(required=True)

    def save_bookmarks(self):
        """Fetch items and store in db."""
        new_bookmarks = []
        pocket_r = pocket_connect.get_pocket_items(self.pocket_access_token, state='all', detailType='complete', count=10)
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
        return new_bookmarks

class Bookmark(db.Model):
    user = db.ReferenceProperty(User, collection_name='bookmarks')
    url = db.StringProperty(required=True)
    title = db.StringProperty()
    has_been_read = db.BooleanProperty()
    is_favorite = db.BooleanProperty()
    excerpt = db.TextProperty()
    tags = db.TextProperty()
    word_count = db.IntegerProperty()

class MainHandler(webapp2.RequestHandler):
    def get(self):
        request_token = pocket_connect.get_request_token()
        redirect_uri = 'http://localhost:14080/access?request_token=%s' % request_token
        self.redirect(str('https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s' % (request_token,redirect_uri)))

class AccessHandler(webapp2.RequestHandler):
    def get(self):
        request_token = self.request.get('request_token')
        credentials = pocket_connect.get_credentials(request_token)
        user = User(username=credentials['username'], pocket_access_token=credentials['access_token'])
        user.put()
        user.save_bookmarks()
        self.redirect('/users?user_key='+str(user.key()))

class UsersHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(User.get(self.request.get('user_key')).bookmarks.fetch(1000))

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/access', AccessHandler),
    ('/users', UsersHandler)
], debug=True)
