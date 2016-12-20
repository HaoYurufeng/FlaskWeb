#!/usr/bin/env python
# -*- coding:utf8 -*-

from datetime import datetime
from flask import render_template, abort, flash, redirect, url_for, request, current_app
from . import main
from ..models import User, Role, Post, Permission
from forms import EditProfileAdminForm, PostForm
from app import db
from ..decorators import admin_required
from flask_login import login_required, current_user

@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts, pagination=pagination, current_time=datetime.utcnow())

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)

@main.route('/edit-profile/<string:username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    form = EditProfileAdminForm(user)
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
    return render_template('edit_profile.html', form=form, user=user)

@main.route('/user-list', methods=['GET'])
@login_required
@admin_required
def output_user_list():
    users = User.query.all()
    list = []
    for user in users:
        list.append(user.username)
    return render_template('user_list.html', list=list, current_time=datetime.utcnow())

@main.route('/post/<int:id>')
def post(id):
    post = Post.query.filter_by(id=id).first()
    if post is None:
        abort(404)
    return render_template('post.html', posts=[post])

@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.filter_by(id=id).first()
    if post is None:
        abort(404)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)

