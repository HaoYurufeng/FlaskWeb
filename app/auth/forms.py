#!/usr/bin/env python
# -*- coding:utf8 -*-

from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from ..models import User

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                                                     'Usernames must have only letters,'
                                                                                     'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registed.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registed.')

class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', validators=[Required()])
    new_password = PasswordField('New Password', validators=[Required(),
                                                             EqualTo('Con_password', message='Passwords must match.')])
    Con_password = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Update Password')

class ForgotPasswordForm(Form):
    email = StringField('Email', validators=[Required()])
    username = StringField('Username', validators=[Required()])
    submit = SubmitField('Confirm')

class ResetPasswordForm(Form):
    email = StringField('Email', validators=[Required()])
    password = PasswordField('New Password', validators=[Required(),
                                                         EqualTo('Con_password', message='Passwords must match.')])
    Con_password = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Reset Password')

class ResetEmailForm(Form):
    email = StringField('New Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Confirm')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

class InformationForm(Form):
    nickname = StringField('Nickname', validators=[Required()])
    name = StringField('Name', validators=[Required()])
    location = StringField('Location', validators=[Required()])
    about_me = StringField('Self-Introduce', validators=[Required()])
    submit = SubmitField('Save')

