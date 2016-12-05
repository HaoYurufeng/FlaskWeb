#!/usr/bin/env python
# -*- coding:utf8 -*-

from flask_wtf import Form
from wtforms import SubmitField, StringField
from wtforms.validators import Required

class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')
