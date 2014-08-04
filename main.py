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
    username = db.StringProperty (required = True)
    pocket_access_token = db.StringProperty (required = True)

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
		self.response.write(credentials)
app = webapp2.WSGIApplication([
    ('/', MainHandler),('/access', AccessHandler)
], debug=True)
