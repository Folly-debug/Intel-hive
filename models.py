from app import db
from flask_login import UserMixin
from flask import Flask, render_template, flash, request
import datetime
from sqlalchemy import Column, Integer, DateTime
from datetime import datetime
datetime.utcnow()


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pwd = db.Column(db.String(300), nullable=False, unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    cti = db.relationship('cti_share', backref='sharer')

    def __repr__(self):
        return '<User %r>' % self.username


class cti_share(db.Model):
    __tablename__ = "cti_share"
    id = db.Column(db.Integer, primary_key=True,
                   autoincrement=True, nullable=False)
    sharer_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=False)
    created_time = db.Column(db.String, default=datetime.now)
    Severity = db.Column(db.String(100))
    Business_Impact = db.Column(db.String(100))
    IP_address = db.Column(db.String(250))
    System_affected = db.Column(db.String(250))
    Domain_name = db.Column(db.String(500))
    Operating_system = db.Column(db.String(100))
    Type_of_cyberattack = db.Column(db.String(250))
    Country_Origin = db.Column(db.String(200))
    Payload_Name = db.Column(db.String(500))
    Payload_Hash = db.Column(db.String(600))
    Source_URL = db.Column(db.String(800))
    Cyberattack_description = db.Column(db.String(1500))
    Mitigation_taken = db.Column(db.String(2000))
    Suricata = db.Column(db.String(2000))
    Yara = db.Column(db.String(2000))
    Sigma = db.Column(db.String(2000))

    def __str__(self):
        return f'cti_share({self.IP_address}, {self.Severity}, {self.System_affected}, {self.Domain_name}, {self.Operating_system}, {self.Type_of_cyberattack}, {self.Country_Origin}, {self.Payload_Hash}, {self.Payload_Name}, {self.Source_URL}, {self.Attack_infrastructure}, {self.Cyberattack_description}, {self.Mitigation_taken}, {self.Suricata}, {self.Yara}, {self.Sigma})'


class Uploads(db.Model):
    __tablename__ = "uploads"
    id = db.Column(db.Integer, primary_key=True)
    uploads = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


class Recommendations(db.Model):
    __tablename__ = "recommendations"
    id = db.Column(db.Integer, primary_key=True)
    created_time = db.Column(db.String, default=datetime.now)
    Type_of_cyberattack = db.Column(db.String(250))
    data = db.Column(db.LargeBinary)
    Filename = db.Column(db.String(250))
    Sigma = db.Column(db.String(2000))
    Suricata = db.Column(db.String(2000))
    Yara = db.Column(db.String(2000))


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file = db.Column(db.String(255), nullable=False)
    Type_of_cyberattack = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.String, default=datetime.now, nullable=False)


class Feeds(db.Model):
    __tablename__ = "news_feeds"
    id = db.Column(db.Integer, primary_key=True)
    created_time = db.Column(db.String, default=datetime.now)
    title = db.Column(db.String())
    content = db.Column(db.String())
    news_url = db.Column(db.String(), unique=True)
    date_posted = db.Column(db.String())
    def __repr__(self):
        return f'news_feeds({self.title},{self.content},{self.news_url},{self.date_posted})'
