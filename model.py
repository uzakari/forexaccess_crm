import os
from flask import Flask, current_app, render_template
from itsdangerous import TimedJSONWebSignatureSerializer as serilizer
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_admin import Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin
from flask_mail import Mail, Message
import jwt
from hashlib import md5
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fxcrm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LebczEUAAAAAH2cgnbUVFK-Cwv2DrLID4xHEkC2'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LebczEUAAAAAGlXAFCBtN5TYv-X4cRvJkhKhuJd'
app.config['SECRET_KEY'] ='GoodboyUltimate'
app.config['TESTING'] = False
app.config.from_pyfile('config.cfg')

admin = Admin(app)

boo = Bootstrap(app)

db = SQLAlchemy(app)

moment = Moment(app)

manger = Manager(app)

migrate = Migrate(app, db)
manger.add_command('db', MigrateCommand)

mail = Mail(app)


login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

app.config.update(

)


class UserData(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(79), unique=True)
    f_name = db.Column(db.String(60))
    l_name = db.Column(db.String(60))
    phone = db.Column(db.String(20))
    country = db.Column(db.String(10))
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    confirmed = db.Column(db.Boolean, default=False)
    about_me = db.Column(db.String(240))
    account_monthly = db.Column(db.String(500))
    account_balance = db.Column(db.String(500))
    withdrawal = db.relationship('WithDrawal', backref='withdrawal_owner', lazy='dynamic')

    def __repr__(self):
        return '<User %r>' % self.f_name

    @property
    def password(self):
        raise AttributeError('password is not a reasable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation(self, expires_in=3600):
        s = serilizer(app.config['SECRET_KEY'], expires_in=expires_in)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = serilizer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        else:
            self.confirmed = True
            db.session.add(self)
            db.session.commit()
            return True

    def generate_password_reset(self):
        return jwt.encode({'reset_password': self.id}, app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password(token):
        try:
           id = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')['reset_password']
        except:
            return
        return UserData.query.get(id)

    def avatar(self, size):
        avi = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/?d=identicon&s={}'.format(avi, size)


@login_manager.user_loader
def load_user(user_id):
    return UserData.query.get(int(user_id))


class Permission:
    REGACC = 2
    EDITACC = 4
    VIEWACC = 8
    ADMIN = 16


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('UserData', backref='role')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def __repr__(self):
        return '<Role %r>' % self.name

    def has_permission(self, prem):
        return self.permissions & prem == prem

    def add_permission(self, prem):
        if not self.has_permission(prem):
            self.permissions += prem

    def remove_permission(self, prem):
        if self.has_permission(prem):
            self.permissions -= prem

    def reset_permission(self):
        self.permissions = 0

    @staticmethod
    def insert_role():
        roles = {
            'User': [Permission.REGACC],
            'Sales': [Permission.VIEWACC, Permission.REGACC],
            'Administrator': [Permission.REGACC, Permission.VIEWACC, Permission.EDITACC, Permission.ADMIN]
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permission()
            for prem in roles[r]:
                role.add_permission(prem)
            role.default = (role.name == default_role)  # returning true or false
            db.session.add(role)
        db.session.commit()
        

class WithDrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.String(159))
    reason = db.Column(db.String(240))
    user_withdraws = db.Column(db.Integer, db.ForeignKey(UserData.id))

    def __repr__(self):
        return '<With_Drawal%r>' % self.id
# def send_async_email(app, data):
#     with app.app_context():
#         mail.send(data)


def send_email(to, subject, template, **kwargs):
    data = Message(subject, sender='uzakari84@gmail.com', recipients=[to])
    data.body = render_template(template + '.txt', **kwargs)
    data.html = render_template(template + '.html', **kwargs)
    with app.app_context():
        mail.send(data)

admin.add_view(ModelView(UserData, db.session))

if __name__ == '__main__':
    manger.run()