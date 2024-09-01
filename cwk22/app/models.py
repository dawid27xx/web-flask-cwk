from app import db
from flask_login import UserMixin
from datetime import *
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    fullname = db.Column(db.String(30), nullable=False)
    uniyear = db.Column(db.Integer, nullable=False)
    uniemail = db.Column(db.String(30), nullable=False)
    posts = db.relationship('Post', backref='creator')
    groups = db.relationship('Membership', backref='member')
    liked_posts = db.relationship('Post', backref="liked")
    comments = db.relationship('Comment', backref="commenter")

    # password hashing
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, username, password_hash, fullname, uniyear, uniemail):
        self.username = username
        self.password_hash = password_hash
        self.fullname = fullname
        self.uniyear = uniyear
        self.uniemail = uniemail

    def is_authenticated(self):
        return True

    def get_id(self):
        return self.id


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow())
    likes = db.Column(db.Integer, default=0)
    domain = db.Column(db.String(20), default="feed")
    comments = db.relationship("Comment", backref="com")

    def __init__(self, content, creator_id, domain, date):
        self.content = content
        self.creator_id = creator_id
        self.domain = domain
        self.likes = 0
        self.date = datetime.utcnow()

    def like(self):
        self.likes += 1

    def unlike(self):
        self.likes -= 1

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow())
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))

class LikesTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __init__(self, post_id, user_id):
        self.post_id = post_id
        self.user_id = user_id


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), nullable=False)
    members = db.relationship('Membership', backref="group")

    def __init__(self, title):
        self.title = title


class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def get_userid(self):
        return self.user_id
