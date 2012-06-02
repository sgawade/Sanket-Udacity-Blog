import webapp2
import jinja2
import os
import re
import json
import time

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), autoescape = True)

USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASSWD_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

import cgi
def escape_html(s):
    return cgi.escape(s, quote = True)

def top_blogs(update = False):
    key = 'top_blogs'
    blogs = memcache.get(key)
    update_time = memcache.get('update_time')
    if update_time is None:
        update_time = time.time()
    if blogs is None or update:
        blogs = db.GqlQuery("select * from Blogs "
                           "Order by created desc "
                           "limit 10")
        blogs = list(blogs)
        memcache.set(key, blogs)
        update_time = time.time()
        memcache.set('update_time', update_time)
    return blogs, int(time.time() - update_time)

def get_blog(blog_id):
    key = 'blog'
    if blog_id == memcache.get('blog_id'):
        blog = memcache.get(key)
    else:
        blog = None
    u_time = memcache.get('u_time')
    if u_time is None:
        u_time = time.time()
    if blog is None:
        blog = Blogs.get_by_id(int(blog_id))
        memcache.set(key, blog)
        memcache.set('blog_id', blog_id)
        u_time = time.time()
        memcache.set('u_time', u_time)
    return blog, int(time.time() - u_time)

class Blogs(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class MainPage(webapp2.RequestHandler):
    def get(self):
        blogs, update_time = top_blogs()
        temp_vars = {'blogs': blogs, 'u_time': update_time}
        template = jinja_environment.get_template('templates/home.html')
        self.response.out.write(template.render(temp_vars))

class NewPost(webapp2.RequestHandler):
    def render_front(self, subject="", content="", error=""):
        temp_vars = {'error': error, 'subject': escape_html(subject), 'content': escape_html(content)}
        template = jinja_environment.get_template('templates/blog_form.html')
        self.response.out.write(template.render(temp_vars))

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            a = Blogs(subject = subject, content = content)
            blog_id = a.put()
            top_blogs(True)
            self.redirect("/blog/%d" % blog_id.id())
        else:
            self.render_front(subject, content,"subject and content, please!")


class Permalink(webapp2.RequestHandler):
    def get(self, blog_id):
        blog, u_time = get_blog(blog_id)
        template = jinja_environment.get_template('templates/blog.html')
        self.response.out.write(template.render({'b': blog, 'u_time': u_time}))

def valid_username(username):
    return USER_RE.match(username)

def valid_passwd(password):
    return PASSWD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

import hmac
SECRET = 'sanketgawade'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

class SignUp(webapp2.RequestHandler):
    def write_page(self, username="", usernameerror="", passwd="", passwderror="", verify="", verifyerror="", email="", emailerror=""):
        template = jinja_environment.get_template('templates/signup_form.html')
        self.response.out.write(template.render({
                                        "username": username,
                                        "usernameerror": usernameerror,
                                        "passwd": passwd,
                                        "passwderror": passwderror,
                                        "verify": verify,
                                        "verifyerror": verifyerror,
                                        "email": email,
                                        "emailerror": emailerror
                                       }))

    def get(self):
        self.response.headers.add_header('Set-Cookie', ' ')
        self.write_page()

    def post(self):
        u_username = self.request.get("username")
        u_password = self.request.get("password")
        u_verify = self.request.get("verify")
        u_email = self.request.get("email")

        if u_username:
            if not valid_username(u_username):
                username = u_username
                usernameerror = "That's not a valid username."
                v_username = None
            else:
                u_db = db.GqlQuery("select * from Users WHERE name='%s'" %u_username)
                if u_db.fetch(1):
                    username = u_username
                    usernameerror = "The User Already exists"
                    v_username = None
                else:
                    username = u_username
                    usernameerror = ""
                    v_username = True
        else:
            username = u_username
            usernameerror = "That's not a valid username."
            v_username = None

        if u_password:
            if valid_passwd(u_password):
                if u_password == u_verify:
                    passwd = ""
                    passwderror = ""
                    verify = ""
                    verifyerror = ""
                    v_passwd = True
                    v_verify = True
                else:
                    passwd = ""
                    passwderror = ""
                    verify = ""
                    verifyerror = "Your passwords didn't match."
                    v_passwd = None
                    v_verify = None
            else:
                passwd = ""
                verify = ""
                passwderror = "That wasn't a valid password."
                verifyerror = ""
                v_passwd = None
                v_verify = None
        else:
            passwd = ""
            verify = ""
            passwderror = "That wasn't a valid password."
            verifyerror = ""
            v_passwd = None
            v_verify = None

        if u_email:
            if not valid_email(u_email):
                email = u_email
                emailerror = "That's not a valid email."
                v_email = None
            else:
                email = u_email
                emailerror = ""
                v_email = True
        else:
            email = u_email
            emailerror = ""
            v_email = True

        if not (v_username and v_passwd and v_verify and v_email):
            self.write_page(username, usernameerror, passwd, passwderror, verify, verifyerror, email, emailerror)
        else:
            hpwd = hash_str(u_password)
            a = Users(name=username, password=hpwd, email=email)
            userid = a.put()
            self.response.headers.add_header('Set-Cookie', 'user_id=' + str(userid.id()) + '|' + hpwd +'; Path=/')
            self.redirect("/blog/welcome")

class LoginPage(webapp2.RequestHandler):
    def get(self):
        template = jinja_environment.get_template('templates/login.html')
        self.response.out.write(template.render())

    def post(self):
        u_username = self.request.get("username")
        u_password = self.request.get("password")
        u_db = db.GqlQuery("select * from Users WHERE name='%s'" %u_username).get()
        if not u_db:
            template = jinja_environment.get_template('templates/login.html')
            self.response.out.write(template.render({'login_error': "Invalid login", 'username': u_username}))
        else:
            u_id = u_db.key().id()
            result = Users.get_by_id(int(u_id))
            hpwd = hash_str(u_password)
            if result.password == hpwd:
                self.response.headers.add_header('Set-Cookie', 'user_id=' + str(u_id) + '|' + hpwd +'; Path=/')
                self.redirect("/blog/welcome")
            else:
                template = jinja_environment.get_template('templates/login.html')
                self.response.out.write(template.render({'login_error': "Invalid login", 'username': u_username}))

class WelcomePage(webapp2.RequestHandler):
    def get(self):
        user_cookie = self.request.cookies.get('user_id')
        if user_cookie:
            u_id = user_cookie.split('|')[0]
            hpwd = user_cookie.split('|')[1]
            result = Users.get_by_id(int(u_id))
            if result:
                if result.password == hpwd:
                    self.response.out.write("Welcome, %s!"  %result.name) 
                else:
                    self.redirect("/blog/signup")
            else:
                self.redirect("/blog/signup")
        else:
            self.redirect("/blog/signup")

class LogoutPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')
        self.redirect("/blog/signup")

class PermalinkJson(webapp2.RequestHandler):
    def get(self, blog_id):
        self.response.headers['Content-Type'] =  'application/json'
        blog = Blogs.get_by_id(int(blog_id))
        result = json.dumps({'content': blog.content, 'created': blog.created.strftime("%a %b %d %I:%M:%S %Y"), 'subject': blog.subject})
        self.response.out.write(result) 

class MainPageJson(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] =  'application/json'
        blogs = db.GqlQuery("select * from Blogs "
                           "Order by created desc ")
        blogs = list(blogs)
        result = []
        for blog in blogs:
            result.append({'content': blog.content, 'created': blog.created.strftime("%a %b %d %I:%M:%S %Y"), 'subject': blog.subject})
        result = json.dumps(result)
        self.response.out.write(result)

class Flush(webapp2.RequestHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/blog")

    
app = webapp2.WSGIApplication([
                               (r'/blog', MainPage),
                               (r'/blog/flush', Flush),
                               (r'/blog/signup', SignUp),
                               (r'/blog/login', LoginPage),
                               (r'/blog/logout', LogoutPage),
                               (r'/blog/welcome', WelcomePage),
                               (r'/blog/newpost', NewPost),
                               (r'/blog/(\d+)', Permalink),
                               (r'/blog/([0-9]+).json', PermalinkJson),
                               (r'/blog/.json', MainPageJson)
                              ],
                              debug=True)
