import smtplib
from datetime import datetime
from functools import wraps
import os
from dotenv import load_dotenv
import secrets
from flask import Flask, render_template, request, url_for, redirect, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_required, logout_user, login_user, current_user
from flask_gravatar import Gravatar
import sqlalchemy.exc
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from forms import NewPostForm, RegisterForm, LoginForm, CommentForm


load_dotenv()
GMAIL_USERNAME = os.getenv("GMAIL_USERNAME")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex()
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///blog.db")

db = SQLAlchemy(app)

ckeditor = CKEditor(app)

Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=35,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    name = db.Column(db.String(1000), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(1000), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    try:
        user = db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one()
    except sqlalchemy.exc.NoResultFound:
        return None
    else:
        return user


# Admin Only Decorator Function
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        return abort(403)
    return wrapper


@app.route("/")
@app.route("/home")
def home():
    all_posts = db.session.execute(db.Select(BlogPost)).scalars().all()
    return render_template("index.html", posts=all_posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        pwhash = generate_password_hash(register_form.password.data, method="pbkdf2:sha256:10", salt_length=8)
        try:
            db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
        except sqlalchemy.exc.NoResultFound:
            new_user = User(
                email=email,
                password=pwhash,
                name=register_form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("home"))
        else:
            flash("This email already exists. Please log in instead.")
            return redirect(url_for("login"))
    return render_template("register.html", form=register_form)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        try:
            user = db.session.execute(db.select(User).filter_by(email=login_form.email.data)).scalar_one()
        except sqlalchemy.exc.NoResultFound:
            flash("Invalid credentials. Please try again.")
            return redirect(url_for("login"))
        else:
            if check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for("home"))
            else:
                flash("Invalid credentials. Please try again.")
    return render_template("login.html", form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
@login_required
def add_new_post():
    new_post_form = NewPostForm()
    if new_post_form.validate_on_submit():
        new_post = BlogPost(
            title=new_post_form.title.data,
            date=datetime.now().strftime("%B %d, %Y"),
            body=new_post_form.body.data,
            author=current_user,
            img_url=new_post_form.img_url.data,
            subtitle=new_post_form.subtitle.data,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=new_post_form, is_edit=False)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.session.execute(db.Select(BlogPost).filter_by(id=post_id)).scalar_one()
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        # regex_pattern = re.compile("<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});")
        # comment_text = re.sub(regex_pattern, "", comment_form.comment_text.data)
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.comment_text.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        flash("Please register or log in to comment.")
        return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = db.session.execute(db.select(BlogPost).filter_by(id=post_id)).scalar_one()
    # edit_form = CreatePostForm(
    #     title=post.title,
    #     subtitle=post.subtitle,
    #     author=post.author,
    #     img_url=post.img_url,
    #     body=post.body
    # )
    # if edit_form.validate_on_submit():
    #     post.title = edit_form.title.data
    #     post.subtitle = edit_form.subtitle.data
    #     post.author = edit_form.author.data
    #     post.img_url = edit_form.img_url.data
    #     post.body = edit_form.body.data
    #     db.session.commit()
    edit_form = NewPostForm(obj=post)
    if edit_form.validate_on_submit():
        edit_form.populate_obj(post)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete-post/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    post = db.session.execute(db.select(BlogPost).filter_by(id=post_id)).scalar_one()
    delete_comments = Comment.__table__.delete().where(Comment.post_id == post_id)
    db.session.delete(post)
    db.session.execute(delete_comments)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):
    comment = db.session.execute(db.select(Comment).filter_by(id=comment_id)).scalar_one()
    if current_user.id == 1 or current_user == comment.comment_author:
        parent_post_id = comment.parent_post.id
        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=parent_post_id))
    return abort(403)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == "POST":
        data = request.form
        send_email(data["name"], data["email"], data["phone"], data["message"])
        return render_template("contact.html", msg_sent=True)
    return render_template("contact.html", msg_sent=False)


def send_email(name, email, phone, message):
    with smtplib.SMTP(host="smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(GMAIL_USERNAME, GMAIL_PASSWORD)
        connection.sendmail(
            from_addr=GMAIL_USERNAME,
            to_addrs=GMAIL_USERNAME,
            msg=f"Subject: Contact Form Submission\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        )


if __name__ == "__main__":
    app.run()
