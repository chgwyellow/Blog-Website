import os
from datetime import date
from typing import List
from flask import Flask, abort, render_template, redirect, request, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import ForeignKey, Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Create a User table for all your registered users
class User(UserMixin, db.Model):
    __tablename__ = "user_info"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))

    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # The "text" refers to the text property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# CONFIGURE TABLES
class BlogPost(UserMixin, db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("user_info.id"))
    # Create reference to the User object.
    # The "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __table__name = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # Create Foreign Key, "user_info.id" refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("user_info.id"))
    # Create reference to the User object.
    # The "posts" refers to the text property in the User class.
    comment_author = relationship("User", back_populates="comments")

    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Create a User table for all your registered users.
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(code=403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


with app.app_context():
    db.create_all()


# Register new users into the User database.
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).where(User.email == form.email.data)
        ).scalar()

        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        # Hashed and salted the password
        hash_and_salted_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)  # type: ignore

        new_user = User(
            email=form.email.data,  # type: ignore
            password=hash_and_salted_password,  # type: ignore
            name=form.name.data,  # type: ignore
        )
        db.session.add(new_user)
        db.session.commit()

        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template(
        "register.html", form=form, logged_in=current_user.is_authenticated
    )


# Retrieve a user from the database based on their email.
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if not user:
            # Wrong email address
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):  # type: ignore
            # Wrong password
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user=user)
            return redirect(url_for("get_all_posts"))

    return render_template(
        "login.html", form=form, logged_in=current_user.is_authenticated
    )


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/")
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template(
        "index.html", all_posts=posts, logged_in=current_user.is_authenticated
    )


# Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment!")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,  # type: ignore
            author_id=current_user.id,  # type: ignore
            post_id=requested_post.id,  # type: ignore
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template(
        "post.html",
        post=requested_post,
        logged_in=current_user.is_authenticated,
        form=comment_form,
    )


# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,  # type: ignore
            subtitle=form.subtitle.data,  # type: ignore
            body=form.body.data,  # type: ignore
            img_url=form.img_url.data,  # type: ignore
            author=current_user,  # type: ignore
            date=date.today().strftime("%B %d, %Y"),  # type: ignore
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template(
        "make-post.html", form=form, logged_in=current_user.is_authenticated
    )


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data  # type: ignore
        post.subtitle = edit_form.subtitle.data  # type: ignore
        post.img_url = edit_form.img_url.data  # type: ignore
        post.author = current_user  # type: ignore
        post.body = edit_form.body.data  # type: ignore
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template(
        "make-post.html",
        form=edit_form,
        is_edit=True,
        logged_in=current_user.is_authenticated,
    )


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=False)
