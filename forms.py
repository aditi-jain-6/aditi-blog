from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Email
from flask_ckeditor import CKEditorField


class NewPostForm(FlaskForm):
    title = StringField(label="Blog Post Title", name="title", validators=[InputRequired()])
    subtitle = StringField(label="Subtitle", name="subtitle", validators=[InputRequired()])
    img_url = StringField(label="Blog Image URL", name="img_url", validators=[InputRequired()])
    body = CKEditorField(label="Blog Content", name="body", validators=[InputRequired()])
    submit = SubmitField(label="Submit Post", name="submit")


class RegisterForm(FlaskForm):
    email = EmailField(label="Email", name="email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", name="password", validators=[InputRequired()])
    name = StringField(label="Name", name="name", validators=[InputRequired()])
    submit = SubmitField(label="Sign me up!", name="submit")


class LoginForm(FlaskForm):
    email = EmailField(label="Email", name="email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", name="password", validators=[InputRequired()])
    submit = SubmitField(label="Let me in!", name="submit")


class CommentForm(FlaskForm):
    comment_text = TextAreaField(label="Comment", name="comment", validators=[InputRequired()])
    submit = SubmitField(label="Submit Comment", name="submit")
