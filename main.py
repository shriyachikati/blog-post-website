from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask.cli import load_dotenv
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import email_validator
# Import forms from the forms.py
from dotenv import load_dotenv
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os

load_dotenv()


EMAIL = os.getenv('EMAIL')
PASSWORD = os.getenv('PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# CONFIGURE TABLES
# User table for all the registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(300), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

# BlogPost table to store the data for the blog posts
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")

# Comments table to store all the comments from the user on a post
class Comments(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text: Mapped[str] = mapped_column(String(360), nullable=True)



with app.app_context():
    db.create_all()


# Initialize a gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# Wrapper function to restrict access to only the admin
def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return func(*args, **kwargs)

    return decorated_function


# Register a new user
@app.route('/register', methods=["POST", "GET"])
def register():
    register_form = RegisterForm()

    if request.method == "POST":
        if register_form.validate_on_submit():
            email = request.form.get("email")
            password = request.form.get("password")
            name = request.form.get("name")

            # Check if the email entered by the user has already been registered
            user = db.session.execute(db.select(User).where(User.email==email)).scalar()
            if not user:
                # Hash and salt the password entered by the user
                hashed_and_salted_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

                # Save the user details to the User table
                new_user = User(
                    email = email,
                    password = hashed_and_salted_password,
                    name = name
                )
                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)
                # Redirect the user to the homepage
                return redirect(url_for("get_all_posts"))
            else:
                flash("You have already registered with that email. Try logging in instead.")
                return redirect(url_for("login"))

    return render_template("register.html", form=register_form, current_user=current_user)


# Retrieve a user from the database based on their email
@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()

    if request.method == "POST":
        if login_form.validate_on_submit():
            email = request.form.get("email")
            password = request.form.get("password")

            # Retrieve the details corresponding to the user email
            user = db.session.execute(db.select(User).where(User.email==email)).scalar()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for("get_all_posts"))
                else:
                    flash("Password is incorrect. Please try again.")
                    return redirect(url_for("login"))
            else:
                flash("Email does not match our records. Please try with a different email or register instead.")
                return redirect(url_for("login"))

    return render_template("login.html", form=login_form, current_user=current_user)


# Log out the user and redirect them to the homepage
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# Allow only logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    if request.method == "POST" and not current_user.is_authenticated:
        flash("You need to log in in order to comment.")
        return redirect(url_for("login"))
    else:
        comment_form = CommentForm()
        requested_post = db.get_or_404(BlogPost, post_id)
        if comment_form.validate_on_submit():
            new_comment = Comments(
                text = comment_form.comment.data,
                author_id = current_user.id,
                post_id = post_id
            )
            db.session.add(new_comment)
            db.session.commit()
        return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


# Route to create a new blog post which can only be accessed by the admin
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# Decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# Decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


# Contact me page
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user=EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=EMAIL,
                                to_addrs=EMAIL,
                                msg=f"Subject: New message from blog\n\n"
                                    f"Name: {name}\n"
                                    f"Email: {email}\n"
                                    f"Phone: {phone}\n"
                                    f"Message: {message}\n")
        return render_template("contact.html", text="Successfully sent your message")
    else:
        return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5001)
