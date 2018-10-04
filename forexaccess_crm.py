from flask import url_for, render_template, flash, redirect, request
from datetime import datetime
from forms import UserRegForm, LoginForm, ResetPasswordForm, ResetPasswordForm2, UserEditForm, WithDrawalForm
from model import app, UserData, db, send_email, WithDrawal
from flask_login import login_required, login_user, current_user, logout_user


@app.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('login'))
    return render_template('unconfirmed.html')


@app.before_first_request
def before_request():
    # catch = ['login', 'unconfirmed', 'index.html', 'dashboard', 'logout', 'register', 'confirm']
    if current_user.is_authenticated and not current_user.confirmed:
        return redirect(url_for('unconfirmed'))


@app.route('/')
def index():
    return render_template('index.html', name='user', current_time=datetime.utcnow())


@app.route('/register', methods=['GET','POST'])
def register():
    form = UserRegForm()
    if form.validate_on_submit():
        user = UserData(email=form.email.data,
                        f_name=form.f_name.data,
                        l_name=form.l_name.data,
                        phone=form.phone_no.data,
                        country=form.country.data,
                        password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation()
        send_email(user.email, 'Confirm Your account', 'confirm', user=user, token=token)
        flash('A confirmation has been sent to your mail')
        return redirect(url_for('login'))
    return render_template('registeration.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = UserData.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
                login_user(user, remember=form.remember_me.data)
                return redirect(url_for('dashboard'))
        flash('Invalid Email or Password')
    return render_template('login.html', form=form)


@app.route('/confirm/<token>')
@login_required
def confirmv(token):
    if current_user.confirmed:
        return redirect(url_for('login'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired')
    return redirect(url_for('index'))


@app.route('/reset_password', methods=['GET', 'POST'])
def password_reset():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = UserData.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_password_reset()
            send_email(user.email, 'Forex Access Reset Your Password', 'email_password_reset', user=user, token=token)
        flash('Check Your email for the instructions to reset your password')
    return render_template('password_reset.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def rest_email_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    user = UserData.verify_reset_password(token)
    if not user:
        return redirect(url_for('login'))
    form = ResetPasswordForm2()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('Your Password has been rest')
        return redirect(url_for('login'))
    return render_template('password_rest_change.html', form=form)


@app.route('/user/<int:id>', methods=['GET','POST'])
@login_required
def profile(id):
    user = UserData.query.get_or_404(id)
    form = UserEditForm()
    if form.validate_on_submit():
        user.email = form.email.data
        user.f_name = form.f_name.data
        user.l_name = form.l_name.data
        user.country = form.country.data
        user.phone = form.phone_no.data
        user.about_me =  form.about_me.data
        db.session.add(user)
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('profile', id=user.id))
    form.email.data = user.email
    form.f_name.data = user.f_name
    form.l_name.data = user.l_name
    form.country.data = user.country
    form.phone_no.data = user.phone
    form.about_me.data = user.about_me
    return render_template('user.html', user=user, form=form)


@app.route('/list_table')
def list_table():
    return render_template('table.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.f_name+" "+current_user.l_name)


@app.route('/maps', methods=['GET', 'POST'])
@login_required
def map():
    return render_template('maps.html')


@app.route('/withdrawal', methods=['GET', 'POST'])
@login_required
def withdrawal():
    form = WithDrawalForm()
    if form.validate_on_submit():
        user = UserData.query.filter_by(email=current_user.email).first_or_404()
        t_balance = user.account_balance
        if user:

            if form.Amount_withdraw.data > str(t_balance):
                 flash('You have insufficient balance to make this transaction')
            else:
                withdrawal = WithDrawal(amount=form.Amount_withdraw.data, reason=form.reason.data, withdrawal_owner=current_user)
                db.session.add(withdrawal)
                db.session.commit()
                flash('Your request has been sent. Will be process in 2 working days')
    return render_template('withdrawal.html', form=form)


@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    return render_template('deposit.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been Logged out')
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True, port=2342)
