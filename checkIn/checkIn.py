# all the imports
import os, sys
sys.path.insert(0, os.path.abspath(".."))

import os
import hashlib
import hmac
import random
import argparse
from flask import Flask, request, session, g, redirect, url_for, render_template, abort
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, emit
import sqlalchemy as sa
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from iitlookup import IITLookup
from collections import defaultdict
from datetime import datetime

version = "1.0.0"

app = Flask(__name__, static_url_path='/static', static_folder='static')  # create the application instance :)
socketio = SocketIO(app, manage_session=True)
app.config.from_object(__name__)
app.config.from_pyfile('config.cfg')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

Bootstrap(app)

engine = sa.create_engine(app.config['DB'], pool_recycle=3600, encoding='utf-8')
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
		self.secret = hashlib.pbkdf2_hmac('sha256', bytearray(secret, 'utf-8'), self.salt, 100000)

	def verify_secret(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.salt, 100000)
		return hmac.compare_digest(self.secret, digest)

	def __repr__(self):
		return "<Location %s>" % self.name


class Kiosk(Base):
	__tablename__ = 'kiosks'
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), primary_key=True, nullable=False)
	hardware_id = sa.Column(sa.Integer, primary_key=True, nullable=False)
	token = sa.Column(sa.String(length=65), nullable=False)
	last_seen = sa.Column(sa.DateTime, default=sa.func.now())

	location = relationship('Location')


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


class HawkCard(Base):
	__tablename__ = 'hawkcards'
	sid = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	card = sa.Column(sa.BigInteger, primary_key=True)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'))

	user = relationship('User')
	location = relationship('Location')

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

	trainee = relationship('User', foreign_keys=[trainee_id], back_populates='trainings')
	trainer = relationship('User', foreign_keys=[trainer_id])
	machine = relationship('Machine', foreign_keys=[machine_id])

	def __repr__(self):
		return "<%s trained %s on %s, time=%s>" % \
			   (self.trainee.name, self.trainer.name, self.machine.name, str(self.date))


class User(Base):
	__tablename__ = 'users'
	sid = sa.Column(sa.BigInteger, primary_key=True)
	name = sa.Column(sa.String(length=100), nullable=False)
	type_id = sa.Column(sa.Integer, sa.ForeignKey('types.id'))
	waiverSigned = sa.Column(sa.DateTime)
	photo = sa.Column(sa.String(length=100), default='')
	location_id = sa.Column(sa.INTEGER, sa.ForeignKey('locations.id'), nullable=False, primary_key=True)
	pin = sa.Column(sa.Binary(length=16))
	pin_salt = sa.Column(sa.Binary(length=16))

	def set_pin(self, pin):
		self.pin_salt = os.urandom(16)
		# 100,000 rounds of sha256 w/ a random salt
		self.pin = hashlib.pbkdf2_hmac('sha256', bytearray(pin, 'utf-8'), self.pin_salt, 100000)

	def verify_pin(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.pin_salt, 100000)
		return hmac.compare_digest(self.pin, digest)

	def __repr__(self):
		return "<Location %s>" % self.name

	type = relationship('Type')
	location = relationship('Location')
	trainings = relationship('Training', foreign_keys=[Training.trainee_id])
	access = relationship('Access', order_by='Access.timeIn')

	def __repr__(self):
		return "<User A%d (%s)>" % (self.sid, self.name)


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


# create tables if they don't exist
db_session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(engine)


@app.before_request
def before_request():
	if 'location_id' not in session and request.endpoint != 'auth' and request.endpoint != 'card_read':
		return redirect(url_for('auth'))

	if request.endpoint != 'card_read':
		db = db_session()
		in_lab = db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=session['location_id']) \
			.all() \
			if 'location_id' in session else list()

		g.location = db.query(Location).filter_by(
			id=session['location_id']).one_or_none() if 'location_id' in session else None
		g.students = [a.user for a in in_lab if a.user.type.level <= 0]
		g.staff = [a.user for a in in_lab if a.user.type.level > 0]
		g.staff.sort(key=lambda x: x.type.level, reverse=True)
		g.admin = db.query(User).filter_by(sid=session['admin']).one_or_none() if 'admin' in session else None
		g.version = version


def update_kiosks(location, except_hwid=None):
	db = db_session()
	kiosks = db.query(Kiosk).filter_by(location_id=location)
	if except_hwid:
		kiosks = kiosks.filter(Kiosk.hardware_id != except_hwid)
	kiosks = kiosks.all()
	for kiosk in kiosks:
		socketio.emit('go', {'to': '/', 'hwid': kiosk.hardware_id})



@app.teardown_appcontext
def close_db(error):
	db_session.remove()


@app.route('/auth', methods=['GET', 'POST'])
def auth():
	db = db_session()
	locations = db.query(Location).all()
	if request.method == 'GET':
		return render_template('auth.html', locations=locations)
	else:

		# random_utf8_seq adapted from https://stackoverflow.com/a/1477572
		def byte_range(first, last):
			return list(range(first, last + 1))

		first_values = byte_range(0x00, 0x7F) + byte_range(0xC2, 0xF4)
		trailing_values = byte_range(0x80, 0xBF)

		def random_utf8_seq():
			first = random.choice(first_values)
			if first <= 0x7F:
				return bytes([first])
			elif first <= 0xDF:
				return bytes([first, random.choice(trailing_values)])
			elif first == 0xE0:
				return bytes([first, random.choice(byte_range(0xA0, 0xBF)), random.choice(trailing_values)])
			elif first == 0xED:
				return bytes([first, random.choice(byte_range(0x80, 0x9F)), random.choice(trailing_values)])
			elif first <= 0xEF:
				return bytes([first, random.choice(trailing_values), random.choice(trailing_values)])
			elif first == 0xF0:
				return bytes([first, random.choice(byte_range(0x90, 0xBF)), random.choice(trailing_values),
							  random.choice(trailing_values)])
			elif first <= 0xF3:
				return bytes([first, random.choice(trailing_values), random.choice(trailing_values),
							  random.choice(trailing_values)])
			elif first == 0xF4:
				return bytes([first, random.choice(byte_range(0x80, 0x8F)), random.choice(trailing_values),
							  random.choice(trailing_values)])

		def random_utf8_str(length):
			return "".join(str(random_utf8_seq(), "utf-8") for i in range(length))

		if 'hwid' not in request.form or 'location' not in request.form or 'secret' not in request.form:
			return render_template('auth.html', error='Please complete all fields.', locations=locations)

		location = db.query(Location).filter_by(id=int(request.form['location'])).one_or_none()
		if not location:
			return render_template('auth.html', error='Internal server error: the location went away',
								   locations=locations)
		if not location.verify_secret(request.form['secret']):
			return render_template('auth.html', error='Invalid secret!', locations=locations)

		new_token = random_utf8_str(32)
		kiosk = db.query(Kiosk)\
			.filter_by(location_id=request.form['location'], hardware_id=request.form['hwid'])\
			.one_or_none()

		if kiosk:
			kiosk.token = new_token
		else:
			kiosk = Kiosk(location_id=request.form['location'],
						  hardware_id=request.form['hwid'],
						  token=bytes(new_token, 'utf-8'),
						  last_seen=sa.func.now())
			db.add(kiosk)

		db.commit()

		session['location_id'] = kiosk.location_id
		session['hardware_id'] = int(request.form['hwid'])
		session['token'] = new_token

		return redirect('/')


@app.route('/deauth')
def deauth():
	db = db_session()
	db.query(Kiosk).filter_by(location_id=session['location_id'], hardware_id=session['hardware_id']).delete()
	session.clear()
	return redirect('/auth')


@app.route('/')
def root():
	return render_template('index.html')


@app.route('/card_read/<int:hwid>', methods=['GET', 'POST'])
def card_read(hwid):
	resp = 'Read success: Facility %s, card %s' % (request.form['facility'], request.form['cardnum'])
	db = db_session()
	kiosk = db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard = db.query(HawkCard) \
		.filter_by(card=request.form['cardnum'], location_id=kiosk.location_id) \
		.one_or_none()
	user = dbcard.user if dbcard else None
	socketio.emit('scan', {
		'facility': request.form['facility'],
		'card': request.form['cardnum'],
		'hwid': hwid,
		'sid': user.sid if user else None,
		'name': user.name if user else None,
	})
	print(resp)
	return resp


@app.route('/checkout', methods=['POST'])
def checkout():
	db = db_session()

	card = db.query(HawkCard).filter_by(
		sid=request.args['sid']
	).one_or_none()
	logEntry = CardScan(card_id=card.card, time=sa.func.now(), location_id=session['location_id'])

	location = db.query(Location).filter_by(
		id=session['location_id']
	).one_or_none()

	db.add(logEntry)

	if not location:
		print("Location %d not found" % session['location_id'])

	else:
		lastIn = db.query(Access) \
			.filter_by(location_id=location.id) \
			.filter_by(timeOut=None) \
			.filter_by(sid=card.sid) \
			.one_or_none()

		if lastIn:
			# user signing out
			print("User %s (card id %d) signed out at location %s (id %d, kiosk %d)" % (
				card.user.name, card.card, location.name, location.id, session['hardware_id']
			))
			# sign user out and send to confirmation page
			lastIn.timeOut = sa.func.now()
	db.commit()

	# need to query again for active users now that it's changed
	before_request()
	update_kiosks(session['location_id'], except_hwid=session['hardware_id'])

	if 'next' in request.args:
		return redirect(request.args.get('next'))
	else:
		return success('checkout')


@app.route('/index', methods=['GET'])
def index():
	return redirect('/')


success_messages = defaultdict(tuple)
success_messages.update({
	'login': ("Logged in", "glyphicon-ok"),
	'logout': ("Logged out", "glyphicon-remove"),
	'checkin': ("Welcome", "glyphicon-log-in"),
	'checkout': ("Goodbye", "glyphicon-log-out")
})


@app.route('/success/<action>', methods=['GET'])
def success(action):
	return render_template('success.html', msg=success_messages[action])


@app.route('/banned', methods=['GET'])
def banned():
	return render_template('banned.html')


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
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
	if not request.args.get('sid') and not request.args.get('card'):
		return render_template('admin/login_cardtap.html')
	else:
		if not request.args.get('sid') or not request.args.get('sid').isdigit():
			return render_template('admin/login_cardtap.html',
								   error='This HawkCard is not registered!')

		# check to see if user has a pin
		db = db_session()
		user = db.query(User).filter_by(sid=request.args.get('sid'), location_id=session['location_id']).one_or_none()

		if not user.pin and user.type.level > 0:
			session['admin'] = user.sid
			return render_template('admin/change_pin.html')
		elif user.type.level <= 0:
			return render_template('admin/login_cardtap.html',
								   error='Insufficient permission! This incident will be reported.')

		return render_template('admin/login_pin.html',
							   sid=request.args.get('sid'))


@app.route('/admin/auth', methods=['POST'])
def admin_auth():
	# sanity checks
	db = db_session()
	# check for sufficient permission
	user = db.query(User).filter_by(sid=request.form['sid'], location_id=session['location_id']).one_or_none()
	if user.type.level <= 0:
		return render_template('admin/login_cardtap.html',
							   error='Insufficient permission! This incident will be reported.')
	# check valid pin
	if not user.verify_pin(request.form['pin']):
		return render_template('admin/login_pin.html',
							   error='Invalid PIN!',
							   sid=request.form['sid'])
	# we good
	session['admin'] = user.sid
	return redirect('/admin')


@app.route('/admin/logout', methods=['GET'])
def admin_logout():

	session['admin'] = None
	return redirect(url_for('.success', action='logout'))


@app.route('/admin/change_pin', methods=['GET', 'POST'])
def admin_change_pin():
	if request.method == 'GET':
		return render_template('admin/change_pin.html')
	else:
		db = db_session()
		user = db.query(User).filter_by(sid=session['admin'], location_id=session['location_id']).one_or_none()
		user.set_pin(request.form['pin'])
		db.commit()
		return redirect('/admin')


@app.route('/admin/clear_lab', methods=['GET'])
def admin_clear_lab():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/admin/login')

	db = db_session()
	db.query(Access).filter_by(timeOut=None).update({"timeOut": sa.func.now()}, synchronize_session=False)
	db.commit()
	session['admin'] = None
	return redirect('/success/checkout')

# Admin flow
@app.route('/admin', methods=['GET'])
def admin_dash():
	if g.admin and g.admin.location_id == session['location_id']:
		return render_template('admin/index.html')
	else:
		return redirect('/')


@app.route('/admin/lookup', methods=['GET'])
def admin_lookup():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	db = db_session()
	query = db.query(User)

	sid = request.args.get('sid')
	if sid and sid != '':
		query = query.filter_by(sid=sid)

	name = request.args.get('name')
	access_log = None
	machines = None
	types = None
	ban_type = None
	if name and name != '':
		query = query.filter(User.name.ilike(name + '%'))

	results = query.limit(20).all()

	if len(results) == 1:
		machines = db.query(Machine).filter_by(location_id=session['location_id']).all()
		# if found user has lower rank than admin user
		if results[0].type.level < g.admin.type.level:
			types = db.query(Type).filter_by(location_id=session['location_id']) \
				.filter(Type.level <= g.admin.type.level) \
				.all()
		access_log = db.query(Access) \
			.filter_by(sid=results[0].sid, location_id=session['location_id']) \
			.order_by(Access.timeIn.desc()).limit(10).all()
		ban_type = db.query(Type).filter_by(location_id=session['location_id']) \
			.filter(Type.level < 0) \
			.first()

	return render_template('admin/lookup.html', results=results, machines=machines, types=types, access_log=access_log,
						   now=datetime.now(), ban_type=ban_type, error=request.args.get('error'))


@app.route('/admin/clear_waiver', methods=['GET'])
def admin_clear_waiver():
	if not session['admin']:
		return redirect('/')
	if not request.args.get('sid'):
		return redirect('/admin/lookup')

	db = db_session()
	user = db.query(User).filter_by(sid=request.args.get('sid'),
									location_id=session['location_id']).one_or_none()
	user.waiverSigned = None
	db.commit()
	return redirect('/admin/lookup?sid=' + str(user.sid))


@app.route('/admin/training/add', methods=['POST'])
def admin_add_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	t = Training(trainee_id=int(request.form['student_id']),
				 trainer_id=int(session['admin']),
				 machine_id=int(request.form['machine']),
				 date=sa.func.now())
	db.add(t)
	db.commit()
	return redirect('/admin/lookup?sid=' + str(request.form['student_id']))


@app.route('/admin/training/remove')
def admin_remove_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	training = db.query(Training).filter_by(id=request.args.get('id')).one_or_none()
	sid = 0
	if training:
		sid = training.trainee_id if training else None
		db.delete(training)
		db.commit()
	else:
		sid = request.args.get('sid')

	return redirect('/admin/lookup?sid=' + str(sid))


@app.route('/admin/locations')
def admin_locations():
	pass


@app.route('/admin/locations/remove')
def admin_remove_location():
	pass


@app.route('/admin/locations/update')
def admin_update_location():
	pass


@app.route('/admin/machines')
def admin_machines():
	pass


@app.route('/admin/machines/remove')
def admin_remove_machine():
	pass


@app.route('/admin/machines/update')
def admin_update_machine():
	pass


@app.route('/admin/type/set')
def admin_set_type():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	type = db.query(Type).filter_by(id=request.args['tid'], location_id=session['location_id']).one_or_none()
	user = db.query(User).filter_by(sid=request.args['sid']).one_or_none()
	if not type:
		return redirect('/admin/lookup?sid=' + request.args['sid'] + "&error=Type does not exist.")
	if not user:
		return redirect('/admin/lookup?sid=' + request.args['sid'] + "&error=User does not exist.")
	elif g.admin.type.level < type.level:
		return redirect(
			'/admin/lookup?sid=' + request.args['sid'] + "&error=You don't have permission to set that type.")
	elif user.type.level > g.admin.type.level:
		return redirect(
			'/admin/lookup?sid=' + request.args['sid'] + "&error=You don't have permission to modify that user.")

	user.type_id = request.args['tid']
	db.commit()
	return redirect('/admin/lookup?sid=' + request.args['sid'])


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
		user = db.query(User) \
			.filter_by(sid=request.args.get('sid')) \
			.one_or_none()
		if user:
			user.waiverSigned = sa.func.now()
		db.commit()
		update_kiosks(session['location_id'], except_hwid=session['hardware_id'])
		return redirect('/success/checkin')
	else:
		return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'GET':
		resp = ""
		card_id = request.args.get('card_id')
		name = ""
		sid = ""
		# try:
		il = IITLookup(app.config['IITLOOKUPURL'], app.config['IITLOOKUPUSER'], app.config['IITLOOKUPPASS'])
		resp = il.nameIDByCard(request.args.get('card_id'))
		# except:
		#   print(sys.exc_info()[0])
		if resp:
			sid = resp['idnumber'][1:]
			name = ("%s %s") % (resp['first_name'], resp['last_name'])
		return render_template('register.html',
							   sid=sid,
							   card_id=card_id,
							   name=name)

	elif request.method == 'POST':
		if request.form['name'] == "" or int(request.form['sid']) < 20000000:
			return render_template('register.html', sid=request.form['sid'], card_id=request.form['card_id'],
								   name=request.form['name'])
		db = db_session()
		newtype = db.query(Type) \
			.filter_by(location_id=session['location_id']) \
			.filter_by(level=0) \
			.one_or_none()

		db.add(User(sid=request.form['sid'],
					name=request.form['name'].title(),
					type_id=newtype.id,
					waiverSigned=None,
					location_id=session['location_id']))

		card = db.query(HawkCard).filter_by(card=request.form['card_id']).one_or_none()
		card.sid = request.form['sid']

		db.commit()
		return redirect(url_for('.waiver', sid=request.form['sid']))


@socketio.on('check in')
def check_in(data):
	db = db_session()
	data['card'] = int(data['card'])
	data['facility'] = int(data['facility'])
	data['location'] = int(data['location'])

	server_kiosk = db.query(Kiosk).filter_by(location_id=data['location'], hardware_id=data['hwid']).one_or_none()

	resp = ""

	#if server_kiosk.token.decode('utf-8') != data['token']:
	#    emit('err', {'hwid': session['hardware_id'], 'err': 'Token mismatch'})
	#    emit('go', {'to': '/deauth', 'hwid': session['hardware_id']})
	#    return "Token mismatch!"

	card = db.query(HawkCard).filter_by(
		card=data['card'],
		location_id=data['location']
	).one_or_none()

	location = db.query(Location).filter_by(
		id=data['location']
	).one_or_none()

	if not location:
		resp = ("Location %d not found" % data['location'])

	if not card:
		# check to see if they already have a record
		il = IITLookup(app.config['IITLOOKUPURL'], app.config['IITLOOKUPUSER'], app.config['IITLOOKUPPASS'])
		student = il.nameIDByCard(data['card'])
		sid = int(student['idnumber'].replace('A', ''))

		if not student:
			# user is new and isn't in IIT's database
			db.add(HawkCard(sid=None, card=data['card'], location_id=location.id))
			db.commit()
		elif db.query(User).filter_by(sid=sid).count() > 0:
			# user exists, has a new card
			card = HawkCard(sid=sid, card=data['card'], location_id=location.id)
			db.add(card)
		else:
			# first time in lab
			resp = ("User for card id %d not found" % data['card'])
			db.add(HawkCard(sid=None, card=data['card'], location_id=location.id))

		db.commit()

	if not card.user:
		# send to registration page
		emit('go', {'to': url_for('.register', card_id=data['card']), 'hwid': data['hwid']})

	else:
		lastIn = db.query(Access) \
			.filter_by(location_id=location.id) \
			.filter_by(timeOut=None) \
			.filter_by(sid=card.sid) \
			.one_or_none()
		print(lastIn)

		if card.user.type.level < 0:
			resp = ("User %s (card id %d) tried to sign in at %s but is banned! (id %d, kiosk %d)" % (
				card.user.name, data['card'], location.name, location.id, data['hwid']
			))
			emit('go', {'to': url_for('.banned'), 'hwid': data['hwid']})

		elif lastIn:
			# user signing out
			resp = ("User %s (card id %d) signed out at location %s (id %d, kiosk %d)" % (
				card.user.name, data['card'], location.name, location.id, data['hwid']
			))
			# sign user out and send to confirmation page
			lastIn.timeOut = sa.func.now()
			emit('go', {'to': url_for('.success', action='checkout', name=card.user.name), 'hwid': data['hwid']})
			update_kiosks(location.id, except_hwid=data['hwid'])

		elif card.user.waiverSigned:
			# user signing in
			resp = ("User %s (card id %d) is cleared for entry at location %s (id %d, kiosk %d)" % (
				card.user.name, data['card'], location.name, location.id, data['hwid']
			))
			# sign user in and send to confirmation page
			accessEntry = Access(sid=card.sid, timeIn=sa.func.now(), location_id=location.id)
			db.add(accessEntry)
			emit('go', {'to': url_for('.success', action='checkin', name=card.user.name), 'hwid': data['hwid']})
			update_kiosks(location.id, except_hwid=data['hwid'])

		else:
			# user has account but hasn't signed waiver
			resp = ("User %s (card id %d) needs to sign waiver at location %s (id %d, kiosk %d)" % (
				card.user.name, data['card'],
				location.name, location.id, data['hwid']
			))
			# present waiver page
			emit('go', {'to': url_for('.waiver', sid=card.sid), 'hwid': data['hwid']})

	logEntry = CardScan(card_id=data['card'], time=sa.func.now(), location_id=data['location'])
	db.add(logEntry)

	db.commit()
	print(resp)
	return resp

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Idea Shop Check In App')
	#parser.add_argument('-p', '--port', help='set the port to bind on', type=int)
	parser.add_argument('-a', '--admin', help='invoke admin tools instead of starting the web app', action='store_true')
	parser.add_argument('-l', '--location', help='choose the location to operate on', type=int)
	parser.add_argument('-s', '--secret', help='set a location\'s secret', type=str)
	args = parser.parse_args()

	if args.admin:
		db = db_session()
		location = db.query(Location).filter_by(id=args.location).one_or_none()
		if not location:
			print('Location %d does not exist!' % args.location)
			exit(404)

		if args.secret:
			location.set_secret(args.secret)
			db.commit()
			print('Secret for %s (%d) updated.' % (location.name, location.id))
			exit(0)
		else:
			print('Location %d: %s' % (location.name, location.id))
			exit(0)

	app.jinja_env.auto_reload = True
	app.config['TEMPLATES_AUTO_RELOAD'] = True
	socketio.run(app, host='0.0.0.0', debug=True)
