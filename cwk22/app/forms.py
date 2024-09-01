from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, EmailField, validators
from wtforms.widgets import TextArea
from wtforms.validators import InputRequired, Regexp, Length, EqualTo, NumberRange


class LoginForm(FlaskForm):
    username = StringField('UserName', [InputRequired(),
                                        Regexp(r'^[A-Za-z\s\0-9\@\.\']+$',
                                               message="Invalid Income name: Provide a name using only letters, and the '-' character."),
                                        Length(min=3, max=25,
                                               message="Invalid name length: Provide a name using between 3 and 25 characters")
                                        ])
    password_hash = PasswordField('Password', [InputRequired()])

def leeds_email_check(form, field):
    if not field.data.endswith('@leeds.ac.uk'):
        raise validators.ValidationError('Email must be a Leeds University email.')
       


class RegisterForm(FlaskForm):
    fullname = StringField('UserName', [InputRequired(),
                                        Regexp(r'^[A-Za-z\s\@\.\']+$',
                                               message="Invalid Income name: Provide a name using only letters, and the '-' character."),
                                        Length(min=3, max=25,
                                               message="Invalid name length: Provide a name using between 3 and 25 characters")
                                        ])

    username = StringField('UserName', [InputRequired(),
                                        Regexp(r'^[A-Za-z\s\0-9\@\.\']+$',
                                               message="Invalid Income name: Provide a name using only letters, and the '-' character."),
                                        Length(min=3, max=25,
                                               message="Invalid name length: Provide a name using between 3 and 25 characters")
                                        ])

    uniemail = StringField('Email Address', [validators.DataRequired(), leeds_email_check])

    uniyear = IntegerField("uniyear", [InputRequired(), NumberRange(0,10)])

    password_hash = PasswordField('Password', [InputRequired(),
                                               Length(min=8, max=25,
                                               message="Invalid name length: Provide a password using between 8 and 25 characters"),
                                               EqualTo('password_hash2',
                                                       message='Passwords must be equal')
                                               ])

    password_hash2 = PasswordField('Comfirm Password', [InputRequired()])


class PostForm(FlaskForm):
    content = StringField('Content', [InputRequired()],
                          widget=TextArea())
    creator = StringField("Creator")
    
class CommentForm(FlaskForm):
    content = StringField('Content', [InputRequired()],
                          widget=TextArea())


class GroupForm(FlaskForm):
    title = StringField('Title', [InputRequired()])


class UsernameForm(FlaskForm):
    username = StringField('Username', [InputRequired()])


class PasswordForm(FlaskForm):
    current_password_hash = PasswordField(
        'Current Password', [InputRequired()])
    password_hash = PasswordField('Password', [InputRequired()])
