# all the imports
import os
#import mysql.connector as mariadb
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from flask_bootstrap import Bootstrap
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
#from socketServer import WSServer
from collections import defaultdict

# TODO: consider using flask-login
# or maybe not, they don't seem to support forced reauthentication on 'fresh' logins

app = Flask(__name__) # create the application instance :)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr.db')
))
app.config.from_pyfile('config.cfg')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

Bootstrap(app)

engine = sa.create_engine(app.config['DB'])
Base = declarative_base()
class KioskUser(Base):
    __tablename__ = 'kioskUsers'
    id = sa.Column(sa.BigInteger, primary_key=True)
    card_facility = sa.Column(sa.Integer, nullable=False)
    card_number = sa.Column(sa.Integer, nullable=False)
    name = sa.Column(sa.String)
    a_number = sa.Column(sa.String, nullable=False)
class KioskSignature(Base):
    __tablename__ = 'kioskSignatures'
    id = sa.Column(sa.BigInteger, primary_key=True)
    user_id = sa.Column(sa.BigInteger, sa.ForeignKey('kioskUsers.id'))
    location_id = sa.Column(sa.Integer, sa.ForeignKey('kioskLocations.id'))
    time_signed = sa.Column(sa.DateTime, nullable=False)
class kioskLocation(Base):
    __tablename__ = 'kioskLocations'
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String, nullable=False)
db_session = sa.orm.sessionmaker(bind=engine)

#socket_server = WSServer()
#socket_server.start()

#def connect_db():
#    """Connects to the specific database."""
#    mariadb_connection = mariadb.connect(host='10.0.8.18',user='checkIn',password='iaG0sN2pUOyyuxjdGABzho0c6h7jJls3',database='checkIn')
#    return mariadb_connection

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""

@app.route('/')
def checkIn():
    return render_template('index.html')

@app.route('/index', methods=['GET'])
def index():
    # don't allow just anyone to be a kiosk,
    # otherwise people could conceivably pretend to be here
    if not session['logged_in']:
        return redirect(url_for('start_reading'))

#    db = connect_db()
#    cur = db.cursor()
#    cur.execute('describe scanLog')
#    data = cur.fetchall()
#    print(data)
#    db.close()

    return render_template('index.html', hardware_id=session['hardware_id'])

success_messages = defaultdict(str)
success_messages.update({
    'login':   "You have been logged in.",
    'logout':  "You have been logged out.",
    'checkin': "You have checked in."
})
@app.route('/success/<action>', methods=['GET'])
def success(action):
    return render_template('success.html', msg=messages[action])

@app.route('/card_read', methods=['POST'])
def card_read():
    user = db_session.query(KioskUser).filter(
        KioskUser.card_facility == request.form['card_facility'],
        KioskUser.card_number == request.form['card_number']
    ).one_or_none()
    if not user:
        print("User for card id {}{} not found"
            .format(request.form['card_facility'], request.form['card_number']))
    else:
        signatures = db_session.query(KioskSignature)\
            .filter(KioskSignature.user_id == user.id)\
            .all()
        for signature in signatures:
            if signature.location_id == session['location_id']:
                socket_server.succeed(request.form['hardware_id'])
                return
        print("User {} (card id {}) is not cleared for entry at location {} (id {})"\
            .format(
                user.name, request.form['card_facility'], request.form['card_number'],
                session['location_name'], session['location_id']
            ))
        socket_server.fail(request.form['hardware_id'])

def _login(request):
    error = None
    if request.method == 'POST':
        if (request.form['username'] != app.config['USERNAME']
            or request.form['password'] != app.config['PASSWORD']):
            error = 'Authentication failure'
        else:
            session['logged_in'] = True
    return error

@app.route('/start_reading', methods=['GET', 'POST'])
def start_reading():
    error = _login(request)
    if not error and request.method == "POST":
        hwid = request.form['hardware_id']
        if socket_server.has_connection(hwid):
            error = 'Hardware ID already in use'
        else:
            lid = db_session.query(KioskLocation)\
                .filter(KioskLocation.name == request.form['location'])\
                .one_or_none()
            if not lid:
                error = 'Location not found'
            else:
                session['hardware_id'] = hwid
                session['location_id'] = lid
                session['location_name'] = request.form['location']
                return redirect(url_for('success', action='login'))
    return render_template('login.html', error=error, startup=True)

@app.route('/login', methods=['GET','POST'])
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
