#!/usr/bin/env python
# -*- coding:utf8 -*-

from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, login_required, current_user, logout_user
from app import db
from . import auth
from ..models import User
from forms import LoginForm, RegistrationForm, ChangePasswordForm, ForgotPasswordForm, ResetPasswordForm
from ..email import send_email

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)

        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account', 'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change_pwd', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.new_password.data is None:
            flash('Password can not be Null!')
        elif form.new_password.data is not None and current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            send_email(current_user.email, 'Password Changed', 'auth/email/resetpwd', user=current_user)
            flash('You have successfully changed your password! Please log in again!')
            logout_user()
            return redirect(url_for('auth.login'))
        else:
            flash('Password incorrect, please re-enter!')
    return render_template('auth/updatePWD.html', form=form)


@auth.route('/resetpwd', methods=['GET', 'POST'])
def forgot_pwd():
    """判断当前用户是否登录"""
    if not current_user.is_anonymous:
        logout_user()
        return redirect(url_for('auth.forgot_pwd'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():

        """
        if User.query.filter_by(email=form.email.data, username=form.username.data).first():
            send_email(form.email.data, 'Reset Password', 'auth/email/forgotpwd', user=form.username.data)
        """

        user = User.query.filter_by(email=form.email.data).first()

        """使用token"""

        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Password', 'auth/email/forgotpwd', user=user,
                       token=token, next=request.args.get('next'))
            flash('The email with resetPassword link has been sent to you. Check your inbox! ')
            return redirect(url_for('auth.login'))
        else:
            flash('This email is not registered. Check your email address.')
    return render_template('auth/forgot_pwd.html', form=form)

@auth.route('/resetpwd/<token>', methods=['GET', 'POST'])
def resetPassword(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('This email is not registered. Check your email address.')
        if user.reset_password(token, form.password.data):
            send_email(current_user.email, 'Password Changed', 'auth/email/resetpwd', user=user)
            flash('Successfully Reset! Please login again.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/updatePWD.html', form=form)
