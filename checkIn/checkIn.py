# all the imports
import os
import hashlib
import hmac
from flask import Flask, request, session, g, redirect, url_for, render_template, send_from_directory, abort
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, emit
import sqlalchemy as sa
from sqlalchemy.orm import relationship, joinedload
from sqlalchemy.ext.declarative import declarative_base
from iitlookup import IITLookup
from collections import defaultdict

# TODO: consider using flask-login
# or maybe not, they don't seem to support forced reauthentication on 'fresh' logins

app = Flask(__name__) # create the application instance :)
socketio = SocketIO(app)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr.db')
))
app.config.from_pyfile('config.cfg')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
"""
cbord = IITLookup(
    wsurl=app.config['CBORD_ENDPOINT'],
    user=app.config['CBORD_USER'],
    pwd=app.config['CBORD_PASS']
)
"""
Bootstrap(app)

engine = sa.create_engine(app.config['DB'])
Base = declarative_base()


# New schema
class Location(Base):
    __tablename__ = 'locations'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    name = sa.Column(sa.String(length=50), nullable=False)
    secret = sa.Column(sa.Binary(length=16), nullable=False)
    salt = sa.Column(sa.Binary(length=16), nullable=False)

    def set_secret(self, secret):
        self.salt = os.urandom(16)
        # 100,000 rounds of sha256 w/ a random salt
        self.secret = hashlib.pbkdf2_hmac('sha256', secret, self.salt, 100000)

    def verify_secret(self, attempt):
        return hmac.compare_digest(self.secret, hashlib.pbkdf2_hmac('sha256', attempt, self.salt, 100000))

    def __repr__(self):
        return "<Location %s>" % self.name


class Type(Base):
    __tablename__ = 'types'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    level = sa.Column(sa.Integer, nullable=False)
    name = sa.Column(sa.String(length=50), nullable=False)
    location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

    def __repr__(self):
        return "<Type %s>" % self.name


class Access(Base):
    __tablename__ = 'access'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    sid = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    timeIn = sa.Column(sa.DateTime, nullable=False)
    timeOut = sa.Column(sa.DateTime, default=None)
    location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

    user = relationship('User')
    location = relationship('Location')

    def __repr__(self):
        return "<Access %s(%s-%s)>" % (self.user.name, str(self.timeIn), str(self.timeOut))


class User(Base):
    __tablename__ = 'users'
    sid = sa.Column(sa.BigInteger, primary_key=True)
    name = sa.Column(sa.String(length=100), nullable=False)
    type_id = sa.Column(sa.Integer, sa.ForeignKey('types.id'))
    waiverSigned = sa.Column(sa.DateTime)
    photo = sa.Column(sa.String(length=100), default='')
    location_id = sa.Column(sa.INTEGER, sa.ForeignKey('locations.id'), nullable=False, primary_key=True)
    pin = sa.Column(sa.BigInteger)

    type = relationship('Type')
    location = relationship('Location')

    def __repr__(self):
        return "<User A%d (%s)>" % (self.sid, self.name)


class HawkCard(Base):
    __tablename__ = 'hawkcards'
    sid = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    card = sa.Column(sa.BigInteger, primary_key=True)

    user = relationship('User')

    def __repr__(self):
        return "<HawkCard %d (A%d)>" % (self.card, self.sid)


class Machine(Base):
    __tablename__ = 'machines'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    name = sa.Column(sa.String(length=50))
    location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

    location = relationship('Location')

    def __repr__(self):
        return "<Machine %s>" % self.name


class Training(Base):
    __tablename__ = 'safetyTraining'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    trainee_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    trainer_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    machine_id = sa.Column(sa.Integer, sa.ForeignKey('machines.id'))
    date = sa.Column(sa.DateTime)

    trainee = relationship('User', foreign_keys=[trainee_id])
    trainer = relationship('User', foreign_keys=[trainer_id])
    machine = relationship('Machine', foreign_keys=[machine_id])

    def __repr__(self):
        return "<%s trained %s on %s, time=%s>" %\
               (self.trainee.name, self.trainer.name, self.machine.name, str(self.date))


class AdminLog(Base):
    __tablename__ = 'adminLog'
    id = sa.Column(sa.BigInteger, primary_key=True, autoincrement=True)
    admin_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    action = sa.Column(sa.String(length=50))
    target_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
    data = sa.Column(sa.Text)
    location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'))

    admin = relationship('User', foreign_keys=[admin_id])
    target = relationship('User', foreign_keys=[target_id])
    location = relationship('Location')

    def __repr__(self):
        return "<AdminLog %s (%s) %s, data=%s>" % (self.admin.name, self.action, self.target.name, self.data)


class CardScan(Base):
    __tablename__ = 'scanLog'
    id = sa.Column(sa.BigInteger, primary_key=True, autoincrement=True)
    card_id = sa.Column(sa.BigInteger, sa.ForeignKey('hawkcards.card'), nullable=False)
    time = sa.Column(sa.DateTime)
    location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

    card = relationship('HawkCard')
    location = relationship('Location')

    def __repr__(self):
        return "<CardScan %d at %s>" % (self.card, self.time)


db_session = sa.orm.sessionmaker(bind=engine)
Base.metadata.create_all(engine)


@app.before_request
def update_current_students():
    # TODO: remove this dirty hack
    session['location_id'] = 1

    db = db_session()
    in_lab = db.query(Access)\
        .filter_by(timeOut=None)\
        .all()
    
    g.students = [a.user for a in in_lab if a.user.type.level == 1]
    g.staff = [a.user for a in in_lab if a.user.type.level > 1]
    g.admin = db.query(User).filter_by(sid=session['admin']).one_or_none()\
               if 'admin' in session else None


@app.teardown_appcontext
def close_db(error):
    db_session.close_all()


@app.route('/')
def checkIn():
    return render_template('index.html')


@app.route('/card_read/<int:location_id>', methods=['GET', 'POST'])
def card_read(location_id):
    resp = 'Read success: Facility %s, card %s' % (request.form['facility'], request.form['cardnum'])
    db = db_session()
    dbcard = db.query(HawkCard)\
        .filter_by(card=request.form['cardnum'])\
        .one_or_none()
    user = dbcard.user if dbcard else None
    socketio.emit('scan', {
        'facility': request.form['facility'],
        'card': request.form['cardnum'],
        'location': location_id,
        'sid': user.sid if user else None,
        'name': user.name if user else None,
    })
    print(resp)
    return resp


@app.route('/checkout_button/<int:location_id>', methods=['POST'])
def checkout_button(location_id):
    db = db_session()
    
    card = db.query(HawkCard).filter_by(
        sid=request.args['sid']
    ).one_or_none()
    print(card)
    logEntry = CardScan(card_id=card.card, time=sa.func.now(), location_id=location_id)
    
    location = db.query(Location).filter_by(
        id=location_id
    ).one_or_none()

    db.add(logEntry)

    resp = 'Checkout button pressed.'
    if not location:
        print("Location %d not found" % location_id)

    else:
        lastIn = db.query(Access)\
            .filter_by(location_id=location.id)\
            .filter_by(timeOut=None)\
            .filter_by(sid=card.sid)\
            .one_or_none()
        
        if lastIn:
            # user signing out
            print("User %s (card id %d) signed out at location %s (id %d)" % (
                card.user.name, card.card, location.name, location.id
            ))
            # sign user out and send to confirmation page
            lastIn.timeOut = sa.func.now()
            resp= success('checkout')
    db.commit()
    return resp

@app.route('/index', methods=['GET'])
def index():
    # don't allow just anyone to be a kiosk,
    # otherwise people could conceivably pretend to be here
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('start_reading'))

    return render_template('index.html', hardware_id=session['hardware_id'])

success_messages = defaultdict(str)
success_messages.update({
    'login':   "You have been logged in.",
    'logout':  "You have been logged out.",
    'checkin': "You have checked in.",
    'checkout': "You have checked out."
})


@app.route('/success/<action>', methods=['GET'])
def success(action):
    return render_template('success.html', msg=success_messages[action])


def _login(request):
    error = None
    if request.method == 'POST':
        if (request.form['username'] != app.config['USERNAME']
           or request.form['password'] != app.config['PASSWORD']):
            error = 'Authentication failure'
        else:
            session['logged_in'] = True
    return error


# Admin authentication
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if not request.args.get('sid') and not request.args.get('card'):
        return render_template('admin/login_cardtap.html')
    else:
        if not request.args.get('sid'):
            return render_template('admin/login_cardtap.html',
                                   error='This HawkCard is not registered!')
        return render_template('admin/login_pin.html',
                               sid=request.args.get('sid'))


@app.route('/admin/auth', methods=['POST'])
def admin_auth():
    # sanity checks
    db = db_session()
    # check for sufficient permission
    user = db.query(User).filter_by(sid=request.form['sid']).one_or_none()
    if user.type.level <= 0:
        return render_template('admin/login_cardtap.html',
                               error='Insufficient permission! This incident will be reported.')
    # check valid pin
    pin = int(request.form['pin'])
    if user.pin != pin:
        return render_template('admin/login_pin.html',
                               error='Invalid PIN!',
                               sid=request.form['sid'])
    # we good
    session['admin'] = user.sid
    return redirect('/admin')

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session['admin'] = None
    return redirect('/success/logout')


# Admin flow
@app.route('/admin', methods=['GET'])
def admin_dash():
    if g.admin:
        return render_template('admin/index.html')
    else:
        return redirect('/')


@app.route('/admin/lookup', methods=['GET', 'POST'])
def admin_lookup():
    db = db_session()
    return render_template('admin/lookup.html', results=db.query(User).all())


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = _login(request)
    if not error:
        return redirect(url_for('success', action='login'))
    return render_template('login.html', error=error, startup=False)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('success', action='logout'))


@app.route('/doesExist', methods=['GET'])
def doesExist():
    return render_template('doesExist.html')


@app.route('/newLogin', methods=['GET','POST'])
def newLogin():
    error = None
    success = None
    if request.method == 'POST':
        error = _login(request)
        if not error:
            for k,v in request.form.items():
                if (not v) or (v == ""):
                    error = 'Field ' + k + ' cannot be empty.'
            else:
                success = request.form['newusername']
                # TODO: actually create account
                return render_template('newLogin.html', success=success)
    return render_template('newLogin.html', error=error)


@app.route('/newUser', methods=['GET']) # this doesn't do anything
def newUser():
    return render_template('newUser.html')


@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


@app.route('/waiver', methods=['GET'])
def waiver():
    if not request.args.get('agreed'):
        return render_template('waiver.html', sid=request.args.get('sid'))
    elif request.args.get('agreed') == 'true':
        db = db_session()
        db.add(Access(
            sid=request.args.get('sid'),
            location_id=session['location_id'],
            timeIn=sa.func.now(),
            timeOut=None
        ))
        db.commit()
        return redirect('/success/checkin')
    else:
        # TODO: clear any active session
        return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html',
                               sid=00000000,
                               card_id=request.args.get('card_id'),
                               name='John Doe')

    elif request.method == 'POST':
        db = db_session()
        newtype = db.query(Type)\
            .filter_by(location_id=session['location_id'])\
            .filter_by(level=0)\
            .one_or_none()

        db.add(User(sid=request.form['sid'],
                    name=request.form['name'],
                    type_id=1,
                    waiverSigned=None,
                    location_id=session['location_id']))

        card = db.query(HawkCard)\
            .filter_by(card=request.form['card_id'])\
            .one_or_none()
        card.sid = request.form['sid']

        db.commit()

        return redirect(url_for('.waiver', sid=request.form['sid']))


@socketio.on('check in')
def check_in(data):
    db = db_session()
    data['card'] = int(data['card'])
    data['facility'] = int(data['facility'])
    data['location'] = int(data['location'])
    resp = ""

    logEntry = CardScan(card_id=data['card'], time=sa.func.now(), location_id=data['location'])

    card = db.query(HawkCard).filter_by(
        card=data['card']
    ).one_or_none()

    location = db.query(Location).filter_by(
        id=data['location']
    ).one_or_none()

    db.add(logEntry)

    if not location:
        resp = ("Location %d not found" % data['location'])

    if not card:
        # first time in lab
        resp = ("User for card id %d not found" % data['card'])

        db.add(HawkCard(sid=None, card=data['card']))

    if not card or not card.user:
        # send to registration page
        emit('go', {'to': url_for('.register', card_id=data['card'])})

    else:
        lastIn = db.query(Access) \
            .filter_by(location_id=location.id) \
            .filter_by(timeOut=None) \
            .filter_by(sid=card.sid) \
            .one_or_none()
        print(lastIn)
        if lastIn:
            # user signing out
            resp = ("User %s (card id %d) signed out at location %s (id %d)" % (
                card.user.name, data['card'], location.name, location.id
            ))
            # sign user out and send to confirmation page
            lastIn.timeOut = sa.func.now()
            emit('go', {'to': url_for('.success', action='checkout')})

        elif User.waiverSigned:
            # user signing in
            resp = ("User %s (card id %d) is cleared for entry at location %s (id %d)" % (
                card.user.name, data['card'], location.name, location.id
            ))
            # sign user in and send to confirmation page
            accessEntry = Access(sid=card.sid, timeIn=sa.func.now(), location_id=location.id)
            db.add(accessEntry)
            emit('go', {'to': url_for('.success', action='checkin')})

        else:
            # user has account but hasn't signed waiver
            resp = ("User %s (card id %d) needs to sign waiver at location %s (id %d)" % (
                card.user.name, data['card'],
                location.name, location.id
            ))
            # present waiver page
            emit('go', {'to': url_for('.waiver')})

    db.commit()
    print(resp)
    return resp


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=True)
