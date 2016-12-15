#!/usr/bin/env python
# -*- coding:utf8 -*-

import os
from datetime import datetime
from flask import render_template
from . import main
from ..models import User


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', current_time=datetime.utcnow())

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        os.abort(404)
    return render_template('user.html', user=user)
