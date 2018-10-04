from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, SelectField, ValidationError, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from model import UserData


class LoginForm(FlaskForm):
    email = StringField('Email', [DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', [DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')
    recaptcha = RecaptchaField()


class UserRegForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    f_name = StringField("First Name", validators=[DataRequired()])
    l_name = StringField("Last Name", validators=[DataRequired()])
    phone_no = StringField("Phone", validators=[DataRequired(), Length(10)])
    country = SelectField('Country',
                                choices=[('gh', 'Ghana'), ('sh', 'South Africa'),
                                         ('ng', 'Nigeria'), ('oth', 'Others')])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('cpassword', message='Password Must Match')])
    cpassword = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if UserData.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')


class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm2(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')


class UserEditForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    f_name = StringField("First Name", validators=[DataRequired()])
    l_name = StringField("Last Name", validators=[DataRequired()])
    phone_no = StringField("Phone", validators=[DataRequired(), Length(10)])
    country = SelectField('Country',
                                choices=[('gh', 'Ghana'), ('sh', 'South Africa'),
                                         ('ng', 'Nigeria'), ('oth', 'Others')])
    about_me = TextAreaField('About_me', validators=[DataRequired()])
    submit = SubmitField('Update Profile')


class WithDrawalForm(FlaskForm):
    Amount_withdraw = StringField('Amount', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    submit = SubmitField('Submit')