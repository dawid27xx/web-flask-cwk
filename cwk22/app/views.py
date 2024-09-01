from flask import render_template, flash, redirect, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from datetime import *
from .forms import LoginForm, RegisterForm, PostForm, GroupForm, UsernameForm, PasswordForm, CommentForm
from .models import User, Post, Group, Membership, LikesTable, Comment

# login manager initiation
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# load user


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# feed


@app.route('/', methods=["GET", "POST"])
@login_required
def feed():
    # display all feed posts
    posts = Post.query.filter_by(domain="feed").order_by(Post.date.desc())

    # current liked posts
    liked_posts = []
    likes = LikesTable.query.filter_by(user_id=current_user.id)
    for like in likes:
        for post in posts:
            if like.post_id == post.id:
                liked_posts.append(post)
    # add posts
    form = PostForm()
    if form.validate_on_submit():
        creator = current_user.id

        post = Post(content=form.content.data,
                    date=datetime.utcnow(),
                    creator_id=creator,
                    domain="feed")
        db.session.add(post)
        db.session.commit()
        flash("Added Post Successfully.")
        return redirect("/")
    
    # comment add
    commentform = CommentForm()
    if commentform.validate_on_submit():
        creator = current_user.id
        comment = Comment(content=commentform.content.data,
                          date=datetime.utcnow(),
                          creator_id=creator,
                          post_id=commentform.post.data,
                          )
        db.session.add(comment)
        db.session.commit()
        commentform = CommentForm(formdata=None)
        flash("Added Comment Successfully.")
        return redirect("/")

    
    # comment display
    comments = Comment.query.all()

    return render_template('feed.html',
                           title="Feed",
                           posts=posts,
                           form=form,
                           liked_posts=liked_posts,
                           comments=comments,
                           commentform=commentform)

# group views

# enter group view


@app.route('/entergroup/<int:id>', methods=["GET", "POST"])
@login_required
def entergroup(id):

    form = PostForm()
    if form.validate_on_submit():
        creator = current_user.id

        post = Post(content=form.content.data,
                    creator_id=creator,
                    domain=id,
                    date=datetime.utcnow())

        db.session.add(post)
        db.session.commit()
        flash("Added Post Successfully.")
        return redirect('/entergroup/%s' % ((str(id))))

    # check if in group or not
    member = current_user.id
    group = Group.query.get_or_404(id)
    if Membership.query.filter_by(group_id=id, user_id=member).count() == 0:
        flash("Join the group first!")
        return redirect("/findgroups")

    # see group posts
    posts = Post.query.filter_by(domain=id).order_by(Post.date.desc())

    # check for liked posts
    liked_posts = []
    likes = LikesTable.query.filter_by(user_id=current_user.id)
    for like in likes:
        for post in posts:
            if like.post_id == post.id:
                liked_posts.append(post)

    return render_template("entergroup.html",
                           title=group.title,
                           posts=posts,
                           group=group,
                           form=form,
                           liked_posts=liked_posts)

# leave group

@app.route('/leavegroup/<int:id>', methods=["GET", "POST"])
@login_required
def leavegroup(id):
    group = Group.query.get_or_404(id)
    group1 = group.id
    member = current_user.id
    membership_to_delete = Membership.query.filter_by(
        group_id=group1, user_id=member).first()
    db.session.delete(membership_to_delete)
    db.session.commit()
    flash("Successfully left group")
    return redirect('/findgroups')


# delete group
@app.route('/deletegroup/<int:id>', methods=["GET", "POST"])
@login_required
def deletegroup(id):
    group_to_delete = Group.query.get_or_404(id)
    # delete membership tables
    memberships_to_delete = Membership.query.filter_by(group_id=id)
    for member in memberships_to_delete:
        db.session.delete(member)
    db.session.delete(group_to_delete)
    db.session.commit()
    flash("Successfully deleted group")
    return redirect('/findgroups')

# create group


@app.route('/creategroup', methods=["GET", "POST"])
@login_required
def creategroup():
    form = GroupForm()
    if form.validate_on_submit():
        group = Group(title=form.title.data)
        db.session.add(group)
        db.session.commit()
        joingroup(group.id)
        return redirect("/findgroups")

    return render_template("creategroup.html",
                           form=form)

# join group


@app.route('/joingroup/<int:id>', methods=["GET", "POST"])
@login_required
def joingroup(id):
    # check if already in

    group = Group.query.get_or_404(id)
    group1 = group.id
    member = current_user.id

    new_member = Membership(group_id=group1, user_id=member)
    db.session.add(new_member)
    db.session.commit()
    flash("Successfully joined group")
    return redirect('/entergroup/%s' % ((str(group1))))


@app.route('/findgroups', methods=["GET", "POST"])
@login_required
def find_groups():
    # member count [BROKEN]
    members = Membership.query.count()
    num = members

    # current user memberships
    memberships = Membership.query.filter_by(user_id=current_user.id)
    members_num = Membership

    # user is in
    group_list = []
    # user not in
    group2_list = []

    # sort into two groups
    groups = Group.query.all()
    for group in groups:
        for member in memberships:
            if group.id == member.group_id:
                group_list.append(group)

    for group in groups:
        if group not in group_list:
            group2_list.append(group)

    return render_template("findgroups.html",
                           title="Groups",
                           memberships=memberships,
                           group_list=group_list,
                           members_num=members_num,
                           group2_list=group2_list,
                           num=num)


@app.route('/actionsgroup/<int:id>', methods=["GET", "POST"])
@login_required
def actionsgroup(id):
    return 0

# end of group views

# setting views


@app.route('/settings', methods=["GET", "POST"])
@login_required
def settings():
    return render_template("settings.html",
                           title="Settings")


@app.route('/changeusername', methods=["GET", "POST"])
@login_required
def changeusername():
    users = User.query
    form = UsernameForm()
    if form.validate_on_submit():
        # check for same username
        if current_user.username == form.username.data:
            flash("You can't change to the same username")
            return redirect('/changeusername')
        # check for uniqueness
        for user in users:
            if user.username == form.username.data:
                flash("Username Already Taken")
                return redirect('/changeusername')
        # else, allow and change
        current_user.username = form.username.data
        db.session.commit()
        flash("Successfully changed username to %s" % (form.username.data))
        return redirect('/settings')

    return render_template("changeusername.html",
                           title="Change username",
                           form=form)


@app.route('/changepassword', methods=["GET", "POST"])
@login_required
def changepassword():
    form = PasswordForm()
    if form.validate_on_submit():
        # ask and check for correct current password
        if check_password_hash(current_user.password_hash, form.current_password_hash.data) == False:
            flash("Wrong current password")
            return redirect('/changepassword')
        new_password_hash = generate_password_hash(
            form.password_hash.data, 'sha256')
        current_user.password_hash = new_password_hash
        db.session.commit()
        flash("Successfully changed password")
        return redirect("/settings")
    return render_template('changepassword.html',
                           title="Change Password",
                           form=form)

# post views

# delete post


@app.route('/deletepost/<int:id>')
def deletepost(id):
    post_to_delete = Post.query.get_or_404(id)
    domain = post_to_delete.domain
    if post_to_delete.creator_id == current_user.id:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Successfully deleted post.")
        if domain == 'feed':
            return redirect('/')
        else:
            return redirect('/entergroup/' + domain)
    else:
        flash("Cannot delete other's post")
        return redirect('/')
    
@app.route('/deletepostprofile/<int:id>')
def deletepostprofile(id):
    post_to_delete = Post.query.get_or_404(id)
    domain = post_to_delete.domain
    if post_to_delete.creator_id == current_user.id:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Successfully deleted post.")
        return redirect('/profile')
    else:
        flash("Cannot delete other's post")
        return redirect('/')

# like/unlike  post


@app.route('/like/<int:id>', methods=["GET", "POST"])
def like(id):

    post_liked = Post.query.get_or_404(id)
    existing_like = LikesTable.query.filter_by(
        user_id=current_user.id, post_id=id).first()
    color = "black"

    if existing_like:
        color = "black"
        post_liked.unlike()
        db.session.delete(existing_like)
        db.session.commit()

    else:
        color = "green"
        new_like = LikesTable(user_id=current_user.id, post_id=id)
        db.session.add(new_like)
        post_liked.like()
        db.session.commit()

    new_like_count = post_liked.likes

    return jsonify({'status': 'success', 'like_count': new_like_count, 'color': color})


# user account views

# login
@app.route('/login', methods=["GET", "POST"])
def login():
    # check if user already logged in
    if current_user.is_authenticated:
        flash('Logout first to log in to a different account')
        return redirect('/')
    # login form
    form = LoginForm()
    if form.validate_on_submit():
        # find user by username
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # check password if username exists
            if check_password_hash(user.password_hash, form.password_hash.data):
                login_user(user)
                flash('Successfully logged in user: %s' % (form.username.data))
                return redirect('/')
            else:
                flash("Wrong password - Please try again")
        else:
            flash("Username doesn't exist - Please try again")
            redirect('/login')

    return render_template('loginPage.html',
                           title="LogIn",
                           form=form)

# register


@app.route('/register', methods=["GET", "POST"])
def register():
    # check if user already logged in
    if current_user.is_authenticated:
        flash("Logout first to register a different account.")
        return redirect('/')
    # register user
    form = RegisterForm()
    if form.validate_on_submit():
        # uniqueness check
        users = User.query
        for user in users:
            if form.username.data == user.username:
                flash("Username already taken.")
                return redirect('/register')
            
        # hash password
        hashed_password = generate_password_hash(
            form.password_hash.data, 'sha256')        
       

        user1 = User(username=form.username.data,
                     password_hash=hashed_password,
                     fullname=form.fullname.data,
                     uniyear=form.uniyear.data,
                     uniemail=form.uniemail.data)
        db.session.add(user1)
        db.session.commit()
        flash('Successfully registered user. Please login')
        return redirect('/login')

    return render_template('registerPage.html', form=form,
                           title="Register")

# logout


@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    flash("Successful Logout")
    return redirect('/login')


@app.route('/deleteaccountpage', methods=["POST", "GET"])
@login_required
def deleteaccountpage():
    return render_template("deleteaccountpage.html",
                           title="Delete account")


@app.route('/deleteaccount', methods=["POST", "GET"])
@login_required
def deleteaccount():
    # find current user

    user = User.query.get_or_404(current_user.id)
    logout()

    # delete all links

    memberships = Membership.query.filter_by(user_id=user.id)
    for member in memberships:
        db.session.delete(member)

    posts = Post.query.filter_by(creator_id=user.id)
    for post in posts:
        db.session.delete(post)

    db.session.delete(user)

    db.session.commit()

    flash("Successfully deleted account")
    return redirect('/login')


@app.route('/profile')
@login_required
def profile():
    groups = Group.query
    posts = Post.query.filter_by(creator_id=current_user.id)
    liked_posts = []
    likes = LikesTable.query.filter_by(user_id=current_user.id)
    for like in likes:
        for post in posts:
            if like.post_id == post.id:
                liked_posts.append(post)

    return render_template("profile.html",
                           title="Profile",
                           posts=posts,
                           likes=liked_posts,
                           groups=groups)
