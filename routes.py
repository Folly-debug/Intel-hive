import plotly
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from colorama import Fore, Back, Style
import requests
import string
import re
import numpy as np
import plotly.graph_objs as go

import plotly.express as px
import pandas as pd
import collections
try:
    from collections import abc
    collections.MutableMapping = abc.MutableMapping
except:
    pass

from sqlalchemy import distinct, false, true

import plotly.graph_objects as go
from models import *
from app import db
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
import sqlite3 as sql
from werkzeug.routing import BuildError

import re
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from flask import Flask
from flask import request
from flask import jsonify
from distutils.version import LooseVersion
import json
import random
import string
import time
from app import create_app, db, login_manager, bcrypt
from models import User
from forms import login_form, register_form
from tkinter.font import names
from flask import *
import csv
import io
import pandas as pd
import base64
import os
from werkzeug.utils import secure_filename

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_security import RoleMixin, UserMixin
import logging
import os.path
# logging config
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(filename)s:%(funcName)s:%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO)
# logging config]

app = create_app()
admin = Admin(app, name="intel_hive", template_mode='bootstrap3')
#############################################################################
# CONTROLLER CLASS


class Controller(ModelView):
    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)

    def not_authenticated(self):
        return "You are not authorized to use the admin dashboard!!"


admin.add_views(Controller(User, db.session))
admin.add_view(Controller(cti_share, db.session))


def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers)


UPLOAD_FOLDER = 'C:/Users/Que/Desktop/intelhive_v5/intelhive_v5/static/uploads'

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = ['.txt', '.pdf',
                                    '.png', '.jpg', '.jpeg', '.gif', '.yara', '.yml']
basedir = os.path.abspath(os.path.dirname(__file__))

ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png',
                      '.jpg', '.jpeg', '.gif', '.yar', '.yml'}


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

# landing page


@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    return render_template("index.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/login", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if check_password_hash(user.pwd, form.pwd.data):
                login_user(user)
                return redirect(url_for('index2'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception:
            flash("User doesn't exist!", "danger")

    return render_template("auth.html",
                           form=form,
                           text="Login",
                           title="Login",
                           btn_action="Login"
                           )

# Register route


@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    form = register_form()
    if form.validate_on_submit():
        try:
            email = form.email.data
            pwd = form.pwd.data

            username = form.username.data

            newuser = User(
                username=username,
                email=email,
                pwd=bcrypt.generate_password_hash(pwd),
                is_admin=True
            )

            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
            return redirect(url_for("login"))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")
    return render_template("auth.html",
                           form=form,
                           text="Sign Up",
                           title="Register",
                           btn_action="Register account"
                           )

# Dashboard


@app.route("/dashboard", methods=("GET", "POST"), strict_slashes=False)
def index2():
    result = len(cti_share.query.with_entities(cti_share.Type_of_cyberattack).filter(
        cti_share.Type_of_cyberattack != '').all()) + len(Feeds.query.all())
    return render_template("dashboard.html", result=result)


@app.route("/custform", methods=("GET", "POST"), strict_slashes=False)
def customform():

    if request.method == 'POST':

        IP_address = request.form['IP_address']
        Domain_name = request.form['Domain_name']
        Severity = request.form['Severity']
        Business_Impact = request.form['Business_Impact']
        Operating_system = request.form['Operating_System']
        Payload_Name = request.form['Payload_Name']
        Type_of_cyberattack = request.form['Type_of_cyberattack']
        Country_Origin = request.form['Country_Origin']
        System_affected = request.form['System_affected']
        Source_URL = request.form['Source_URL']
        Cyberattack_description = request.form['Cyberattack_description']
        Mitigation_taken = request.form['Mitigation_taken']
        save_data = cti_share(IP_address=IP_address, Domain_name=Domain_name, Severity=Severity, Operating_system=Operating_system, Payload_Name=Payload_Name, Type_of_cyberattack=Type_of_cyberattack,
                              System_affected=System_affected, Country_Origin=Country_Origin, Business_Impact=Business_Impact, Cyberattack_description=Cyberattack_description, Source_URL=Source_URL, Mitigation_taken=Mitigation_taken)
        db.session.add(save_data)
        db.session.commit()

    return render_template("form.html",

                           )


@app.route('/upload')
def upload():
    logging.info('Showing upload page')
    return render_template('upload.html')


@app.route('/upload', methods=['POST'])
def upload_files():
    """Upload a file."""
    logging.info('Starting file upload')

    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']
    # obtaining the name of the destination file
    filename = file.filename
    if filename == '':
        logging.info('Invalid file')
        flash('No file selected for uploading')
        return redirect(request.url)
    else:
        logging.info('Selected file is= [%s]', filename)
        file_ext = os.path.splitext(filename)[1]
        if file_ext in app.config['ALLOWED_EXTENSIONS']:
            secure_fname = secure_filename(filename)
            file.save(os.path.join(UPLOAD_FOLDER, secure_fname))
            logging.info('Upload is successful')
            flash('File uploaded successfully')
            return redirect('upload')
        else:
            logging.info('Invalid file extension')
            flash('Not allowed file type')
            return redirect(request.url)


@app.route('/download/<path:filename>', methods=['GET'])
def download(filename):
    """Download a file."""
    logging.info('Downloading file= [%s]', filename)
    logging.info(app.root_path)
    full_path = os.path.join(app.root_path, UPLOAD_FOLDER)
    logging.info(full_path)
    return send_from_directory(full_path, filename, as_attachment=True)


@app.route('/files', methods=['GET'])
def list_files():
    """Endpoint to list files."""
    logging.info('Listing already uploaded files from the upload folder.')
    upf = []
    for filename in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.isfile(path):
            upf.append(filename)

    return render_template('mitigation.html', files=upf)


def check_upload_dir():
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/searchtable')
def searchtable():
    ioc = cti_share.query.all()

    search = request.args.get('search[value]')
    if search:
        ioc = ioc.filter(db.or_(
            cti_share.IP_address.like(f'%{search}%'),
            cti_share.Domain_name.like(f'%{search}%'),
            cti_share.Payload_Hash.like(f'%{search}%'),
            cti_share.Payload_Name.like(f'%{search}%'),
            cti_share.Source_URL.like(f'%{search}%'),
            cti_share.Country_Origin.like(f'%{search}%'),
            cti_share.Mitigation_taken.like(f'%{search}%'),
            cti_share.Type_of_cyberattack.like(f'%{search}%'),
            cti_share.created_time.like(f'%{search}%'),
            cti_share.Operating_system.like(f'%{search}%')

        ))
    return render_template("searchtable.html", ioc=ioc)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/mitigation')
def mitigation():
    ioc = cti_share.query.filter(cti_share.id <= 12).all()
    search = request.args.get('search[value]')
    if search:
        ioc = ioc.filter(db.or_(
            cti_share.IP_address.like(f'%{search}%'),
            cti_share.Domain_name.like(f'%{search}%'),
            cti_share.Payload_Hash.like(f'%{search}%'),
            cti_share.Payload_Name.like(f'%{search}%'),
            cti_share.Source_URL.like(f'%{search}%'),
            cti_share.Country_Origin.like(f'%{search}%'),
            cti_share.Mitigation_taken.like(f'%{search}%'),
            cti_share.Type_of_cyberattack.like(f'%{search}%')

        ))

    return render_template("mitigation.html", ioc=ioc)


def variable():
    prev_threat = ''
    return render_template('mitigation.html', prev_threat)


@app.route("/data", methods=("GET", "POST"), strict_slashes=False)
def data():
    return render_template("datastudio.html",
                           )
# Web scapper for hacker news


@app.route("/feeds")
def newsfeeds():
    feeds = Feeds.query.filter(Feeds.id).all()
    search = request.args.get('search[value]')
    if search:
        feeds = feeds.filter(db.or_(
            Feeds.title.like(f'%{search}%'),
            Feeds.content.like(f'%{search}%'),
            Feeds.date_posted.like(f'%{search}%')
            

        ))
    return render_template('feeder.html', feeds=feeds)


@app.route("/news")
def hackernews():
    ua = UserAgent()
    header = {'User-Agent': str(ua.chrome)}
    link = ["https://thehackernews.com/search?updated-max=2022-07-31T00:00:00-07:00&max-results=20", "https://thehackernews.com/"]
    for link in link:
        response = requests.get(link, timeout=5, headers=header)
        soup = BeautifulSoup(response.content, "html.parser")
        title_list = []
        content_list = []
        date_list = []
        links_list = []
        for links in soup.find_all('h2', attrs={"class": "home-title"}):
            title = ''.join(x for x in links.text if x in string.printable).strip()
            title_list.append(title)
        for links in soup.find_all('div', attrs={"class": "home-desc"}):
            content = ''.join(x for x in links.text if x in string.printable).strip()
            content_list.append(content)
        for links in soup.find_all('div', attrs={"class": "item-label"}):
            da = ''.join(x for x in links.text if x in string.printable).strip()
            date_list.append(da)
        for links in soup.find_all('a', attrs={"class": "story-link"}):
            link = links.get('href')
            links_list.append(link)
            # print(f'Link  : {link}')
        if len(title_list)==len(content_list)==len(date_list)==len(links_list):
            title_list=list(reversed(title_list))
            content_list=list(reversed(content_list))
            date_list=list(reversed(date_list))
            links_list=list(reversed(links_list))
            for i in title_list:
                try:
                    title = title_list[title_list.index(i)]
                    content = content_list[title_list.index(i)]
                    date_posted = date_list[title_list.index(i)]
                    news_url = links_list[title_list.index(i)]
                    new_news_feeds = Feeds(
                    title=title,
                    content=content,
                    news_url=news_url,
                    date_posted=date_posted
                        )
                    db.session.add(new_news_feeds)
                    db.session.commit()
                except:
                    db.session.rollback()


if __name__ == "__main__":
    app.run(debug=True)
