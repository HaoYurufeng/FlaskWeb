#!/usr/bin/env python
# -*- coding:utf8 -*-

from datetime import datetime
from flask import render_template
from . import main


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', current_time=datetime.utcnow())
