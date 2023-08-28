from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(message="Invalid mail address"), Email()])
    password = PasswordField(label="Password", validators=[DataRequired(message="Password should be at least 8 chars"),Length(min=8, max=20)])
    name = StringField(label="Name", validators=[DataRequired()])
    submit = SubmitField(label="Sign Me Up!")


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(message="Invalid mail address"), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Log me in!")


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="SUBMIT COMMENT")
