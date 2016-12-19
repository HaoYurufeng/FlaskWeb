#!/usr/bin/env python
# -*- coding:utf8 -*-

from datetime import datetime
from flask import render_template, abort, flash, redirect, url_for
from . import main
from ..models import User, Role
from forms import EditProfileAdminForm
from app import db
from ..decorators import admin_required
from flask_login import login_required


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', current_time=datetime.utcnow())

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return render_template('user.html', user=user)

@main.route('/edit-profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile_admin(username):
    user = User.query.get_or_404(username)
    form = EditProfileAdminForm()
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('Your profile has been updated.')
        return redirect(url_for('main.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('auth/../templates/edit_profile.html', form=form, user=user)

@main.route('/user-list', methods=['GET'])
@login_required
@admin_required
def output_user_list():
    users = User.query.all()
    list = []
    for user in users:
        list.append(user.username)
    return render_template('user_list.html', list=list, current_time=datetime.utcnow())
