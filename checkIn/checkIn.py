# all the imports
import enum
import os, sys

sys.path.insert(0, os.path.abspath(".."))

import os
import base64
import argparse
import zerorpc
import math
import logging
import logging.config
from flask import Flask, request, session, g, redirect, url_for, render_template, abort
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, emit, send
import sqlalchemy as sa
from sqlalchemy.orm import joinedload
from collections import defaultdict
from datetime import datetime, date, timedelta
from typing import Optional, Tuple, List
from checkIn.iitlookup import IITLookup
from checkIn.model import User, UserLocation, Type, Training, Machine, Access, CardScan, Kiosk, Location, HawkCard, \
	Warning, init_db, get_types

version = "1.0.0"

app = Flask(__name__, static_url_path='/static', static_folder='static')  # create the application instance :)
socketio = SocketIO(app, manage_session=True, logger=True)
app.config.from_object(__name__)
app.config.from_pyfile('config.cfg')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

logging.config.dictConfig({
	'version': 1,
	'formatters': {'default': {
		'format': '[%(asctime)s] %(levelname)-7s %(message)s',
		'datefmt': '%m/%d/%Y %I:%M:%S %p'
	}},
	'handlers': {
		'wsgi': {
			'class': 'logging.StreamHandler',
			'stream': 'ext://flask.logging.wsgi_errors_stream',
			'formatter': 'default'
		},
		'file': {
			'level': 'INFO',
			'class': 'logging.handlers.RotatingFileHandler',
			'formatter': 'default',
			'filename': app.config['LOGFILE'],
			'maxBytes': 8000000,
			'backupCount': 3
		}
	},
	'root': {
		'level': 'INFO',
		'handlers': ['wsgi', 'file']
	}
})

Bootstrap(app)

db_session = init_db(app.config['DB'])
default_type, ban_type = get_types()
app.logger.info('Server started.')


@app.before_request
def before_request():
	if 'location_id' not in session \
			and request.endpoint != 'auth' \
			and request.endpoint != 'card_read' \
			and str(request.path[0:7]) != '/static':
		return redirect(url_for('auth'))

	if request.endpoint and request.endpoint != 'card_read' and \
			'socket.io' not in request.path and \
			'static' not in request.path and \
			'/auth' not in request.path:
		db = db_session()
		kiosk = db.query(Kiosk).get(session['hardware_id'])
		if kiosk and kiosk.token == session['token']:
			kiosk.last_seen = sa.func.now()
			kiosk.last_ip = request.remote_addr
			db.commit()
		else:
			return redirect("/auth")

		in_lab = db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=session['location_id']) \
			.options(joinedload(Access.user)) \
			.all() \
			if 'location_id' in session else list()

		g.location = db.query(Location).filter_by(
			id=session['location_id']).one_or_none() if 'location_id' in session else None
		g.students = [a.user for a in in_lab if a.hideStaff or a.user.type.level <= 0]
		g.staff = [a.user for a in in_lab if not a.hideStaff and a.user.type.level > 0]
		g.staff.sort(key=lambda x: x.type.level, reverse=True)
		g.admin = db.query(UserLocation).filter_by(sid=session['admin'], location_id=session['location_id']).one_or_none() if 'admin' in session else None
		g.version = version
		g.kiosk = kiosk

		for student in g.students:
			if not student.get_missing_trainings(db):
				student.general_training = True
			else:
				student.general_training = False


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


@app.errorhandler(Exception)
def exception_handler(error):
	app.logger.error(error, exc_info=True)
	return render_template("internal_error.html"), 500


@app.errorhandler(404)
def error_404(error):
	return render_template("internal_error.html"), 500


@app.route('/error')
def display_error():
	return render_template("internal_error.html"), 500


@app.route('/auth', methods=['GET', 'POST'])
def auth():
	db = db_session()
	locations = db.query(Location).all()
	if request.method == 'GET':
		return render_template('auth.html', locations=locations)
	else:
		if 'hwid' not in request.form or 'location' not in request.form or 'secret' not in request.form:
			return render_template('auth.html', error='Please complete all fields.', locations=locations)

		location = db.query(Location).filter_by(id=int(request.form['location'])).one_or_none()
		if not location:
			return render_template('auth.html', error='Internal server error: the location went away',
			                       locations=locations)
		if not location.verify_secret(request.form['secret']):
			return render_template('auth.html', error='Invalid secret!', locations=locations)

		new_token = base64.urlsafe_b64encode(os.urandom(33)).decode('ascii')
		kiosk = db.query(Kiosk) \
			.filter_by(hardware_id=request.form['hwid']) \
			.one_or_none()

		if kiosk:
			# deauthorize any existing kiosks with that ID
			socketio.emit('go', {'to': url_for('.auth'), 'hwid': kiosk.hardware_id})

			kiosk.token = new_token
			kiosk.location_id = request.form['location']
			kiosk.last_seen = sa.func.now()

		else:
			kiosk = Kiosk(location_id=request.form['location'],
			              hardware_id=request.form['hwid'],
			              token=new_token,
			              last_seen=sa.func.now())
			db.add(kiosk)

		db.commit()

		session['location_id'] = kiosk.location_id
		session['hardware_id'] = int(request.form['hwid'])
		session['token'] = new_token

		return redirect('/')


@app.route('/deauth', methods=["POST"])
def deauth():
	db = db_session()
	db.query(Kiosk).filter_by(location_id=session['location_id'], hardware_id=session['hardware_id']).delete()
	db.commit()
	return redirect('/auth')


@app.route('/deauth/<int:loc>/<int:hwid>', methods=["POST"])
def deauth_other(loc, hwid):
	if not g.admin or g.admin.location_id != session['location_id']or g.admin.type.level < 90:
		return redirect('/')

	socketio.emit('go', {'to': url_for('.deauth'), 'hwid': hwid})

	db = db_session()
	db.query(Kiosk).filter_by(location_id=loc, hardware_id=hwid).delete()
	db.commit()
	return redirect('/admin/locations/' + str(loc))


@app.route('/')
def root():
	if 'admin' in session:
		del session['admin']
		g.admin = None

	return render_template('index.html')


@app.route('/card_read/<int:hwid>', methods=['POST'])
def card_read(hwid):
	resp = 'Read success from HWID %d: Facility %s, card %s' % (hwid, request.form['facility'], request.form['cardnum'])
	db = db_session()
	kiosk = db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard = db.query(HawkCard).filter_by(card=request.form['cardnum']).one_or_none()
	user = dbcard.user if dbcard else None
	socketio.emit('scan', {
		'facility': request.form['facility'],
		'card': request.form['cardnum'],
		'hwid': hwid,
		'sid': user.sid if user else None,
		'name': user.name if user else None,
	})
	logging.getLogger('checkin.card').info(resp)
	return resp

@app.route('/anumber_read/<int:hwid>', methods=['GET'])
def anumber_read(hwid):
	db = db_session()
	card = db.query(HawkCard).filter_by(sid=request.args['anumber'][1:]).first()
	print(card)
	resp = 'Read success from HWID %d: Facility %s, card %s' % (hwid, "null", card.card)
	kiosk = db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard = db.query(HawkCard).filter_by(card=card.card).one_or_none()
	user = dbcard.user if dbcard else None
	socketio.emit('scan', {
		'facility': '2508',
		'card': card.card,
		'hwid': hwid,
		'sid': user.sid if user else None,
		'name': user.name if user else None,
	})
	logging.getLogger('checkin.card').info(resp)
	return resp



@app.route('/checkout', methods=['POST'])
def checkout():
	db = db_session()

	location = db.query(Location).filter_by(
		id=session['location_id']
	).one_or_none()

	if not location:
		logging.getLogger('checkin.checkout').warning("Location %d not found (from kiosk %d)" % (session['location_id'], session['hardware_id']))

	else:
		lastIn = None
		if 'sid' in request.args:
			lastIn = db.query(Access) \
				.filter_by(location_id=location.id) \
				.filter_by(timeOut=None) \
				.filter_by(sid=int(request.args['sid'])) \
				.first()
		elif 'aid' in request.args:
			lastIn = db.query(Access).get(int(request.args['aid']))

		if lastIn:
			# user signing out
			logging.getLogger('checkin.checkout').info("User %s signed out manually at location %s (id %d, kiosk %d)" % (
				lastIn.user.name, location.name, location.id, session['hardware_id']
			))
			# sign user out and send to confirmation page
			lastIn.timeOut = sa.func.now()

			# assign a warning if we need to
			if g.admin and 'warn' in request.form:
				Warning.warn(db, warner=g.admin.sid, warnee=lastIn.sid, reason="Failed to tap out", location=lastIn.location_id, banned=False)

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
	return render_template('success.html', msg=success_messages[action],
	                       show_hide_staff_button=request.args.get('show_hide_staff_button', False),
	                       sid=request.args.get('sid', 0))


@app.route('/banned', methods=['GET'])
def banned():
	return render_template('banned.html')


@app.route('/over_fire_capacity', methods=['GET'])
def over_fire_capacity():
	return render_template('over_fire_capacity.html')


@app.route('/over_staff_capacity', methods=['GET'])
def over_staff_capacity():
	return render_template('over_staff_capacity.html')


@app.route('/needs_training', methods=['GET'])
def needs_training():
	return render_template('needs_training.html')


def _login(request):
	error = None
	if request.method == 'POST':
		if (request.form['username'] != app.config['USERNAME']
				or request.form['password'] != app.config['PASSWORD']):
			error = 'Authentication failure'
		else:
			session['logged_in'] = True
	return error


@app.route('/admin/hideStaff', methods=['POST'])
def admin_hide_staff():
	db = db_session()
	access = db.query(Access).filter_by(sid=request.form.get('sid'), location_id=session['location_id'], timeOut=None) \
		.one_or_none()
	access.hideStaff = not access.hideStaff
	db.commit()
	return redirect('/')


# Admin authentication
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
	if request.method == "GET":
		return render_template('admin/login_cardtap.html')
	else:
		if not request.form.get('sid') or not request.form.get('sid').isdigit():
			return render_template('admin/login_cardtap.html',
			                       error='This HawkCard is not registered!')

		# check to see if user has a pin
		db = db_session()
		user = db.query(UserLocation).filter_by(sid=request.form.get('sid'), location_id=session['location_id']).one_or_none()

		if not user.pin and user.type.level > 0:
			session['admin'] = user.sid
			return render_template('admin/change_pin.html')
		elif user.type.level <= 0:
			return render_template('admin/login_cardtap.html',
			                       error='Insufficient permission! This incident will be reported.')

		return render_template('admin/login_pin.html',
		                       sid=request.form.get('sid'))


@app.route('/admin/auth', methods=['POST'])
def admin_auth():
	# sanity checks
	db = db_session()
	# check for sufficient permission
	user = db.query(UserLocation).filter_by(sid=request.form['sid'], location_id=session['location_id']).one_or_none()
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


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
	session['admin'] = None
	return redirect(url_for('.success', action='logout'))


@app.route('/admin/change_pin', methods=['GET', 'POST'])
def admin_change_pin():
	if request.method == 'GET':
		return render_template('admin/change_pin.html')
	else:
		db = db_session()

		# validate pin
		if request.form['pin'] == '' or request.form['pin'] is None:
			return render_template('admin/change_pin.html', error='Your PIN can not be empty!')

		user = db.query(User).filter_by(sid=session['admin']).one_or_none()
		user.set_pin(request.form['pin'])
		db.commit()
		return redirect('/admin')


# Admin flow
@app.route('/admin', methods=['GET'])
def admin_dash():
	if g.admin and g.admin.location_id == session['location_id']:
		return render_template('admin/index.html')
	else:
		return redirect('/')


@app.route('/admin/warnings/<int:sid>', methods=["GET", "POST"])
def admin_warn(sid):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	db = db_session()

	warnee = db.query(UserLocation).filter_by(sid=sid, location_id=g.admin.location_id).one_or_none()
	warnings = db.query(Warning).filter_by(warnee_id=sid).order_by(sa.desc(Warning.time)).all()

	if warnee is None:
		return render_template('internal_error.html'), 500

	canBan = True
	try:
		check_set_type(userInfo=warnee, typeInfo=ban_type)
	except ProcessingError:
		canBan = False

	if request.method == 'GET':
		return render_template('admin/warnings.html', warnee=warnee, warnings=warnings, admin=g.admin, canBan=canBan)

	reason = request.form.get('reason')
	comments = request.form.get('comments')
	comments = comments if comments else None
	shouldBan = "ban" in request.form
	if not reason or (reason == "Other" and not comments):
		return render_template('admin/warnings.html', warnee=warnee, warnings=warnings, admin=g.admin, reason=reason, comments=comments, canBan=canBan, error="You must input a reason for your " + ("ban" if shouldBan else "warning"))

	if shouldBan:
		try:
			set_type(userID=sid, typeID=ban_type.id)
		except ProcessingError as error:
			return render_template('admin/warnings.html', warnee=warnee, warnings=warnings, admin=g.admin, reason=reason, comments=comments, canBan=False, error=error.message)

	warning = Warning.warn(db, warner=g.admin.sid, warnee=sid, location=session["location_id"], reason=reason, comments=comments, banned=shouldBan)
	db.commit()
	return render_template('admin/warnings.html', warnee=warnee, warnings=[warning] + warnings, canBan=canBan, admin=g.admin)


def lookupQuery(db: sa.orm.session.Session, location_id: int, sid: Optional[int], name: Optional[str], card_no: Optional[int]) -> List[Tuple[UserLocation, int]]:
	warningCounts = db.query(
		Warning.warnee_id,
		sa.func.count(Warning.warnee_id).label("warningCount")
	).group_by(Warning.warnee_id).subquery("warningCounts")
	query = db.query(
		UserLocation,
		sa.func.coalesce(warningCounts.c.warningCount, sa.literal_column("0"))
	) \
		.select_from(UserLocation) \
		.join(User, UserLocation.sid == User.sid) \
		.outerjoin(warningCounts, UserLocation.sid == warningCounts.c.warnee_id) \
		.filter(UserLocation.location_id == location_id)

	if sid or name or card_no:
		if sid:
			query = query.filter(User.sid == sid)
		if name:
			query = query.filter(User.name.ilike(name + "%"))
		if card_no:
			query = query.join(HawkCard, User.sid == HawkCard.sid).filter(HawkCard.card == card_no)
	else:
		query = query.filter(UserLocation.access.any(Access.timeOut == None))
	return query.limit(20).all()


@app.route('/admin/lookup', methods=['GET'])
def admin_lookup():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	db = db_session()

	sid = request.args.get('sid')
	try: sid = int(sid)
	except (TypeError, ValueError): sid = None
	name = request.args.get('name')
	card_id = request.args.get('card')
	try: card_id = int(card_id)
	except (TypeError, ValueError): card_id = None

	location_id = request.args.get('location') if 'location' in request.args else session['location_id']

	access_log = None
	machines = None
	types = None
	trainings = None

	results = lookupQuery(db, location_id, sid, name, card_id)

	if len(results) == 1:
		machines = db.query(Machine).filter_by(location_id=session['location_id']).all()
		# if found user has lower rank than admin user
		if results[0][0].type.level < g.admin.type.level:
			types = db.query(Type).filter(Type.level <= g.admin.type.level).all()
		access_log = db.query(Access) \
			.filter_by(sid=results[0][0].sid, location_id=session['location_id']) \
			.order_by(Access.timeIn.desc()).limit(10).all()

	return render_template('admin/lookup.html', results=results, machines=machines, types=types, access_log=access_log,
	                       now=datetime.now(), error=request.args.get('error'))


@app.route('/admin/clear_waiver', methods=['POST'])
def admin_clear_waiver():
	if not session['admin']:
		return redirect('/')
	if not request.form.get('sid'):
		return redirect('/admin/lookup')

	db = db_session()
	user = db.query(UserLocation).filter_by(sid=request.form.get('sid'),
	                                        location_id=session['location_id']).one_or_none()
	user.waiverSigned = None
	db.commit()
	return redirect('/admin/lookup?sid=' + str(user.sid))


@app.route('/admin/clear_lab', methods=['POST'])
def admin_clear_lab():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/admin/login')

	db = db_session()
	query = db.query(Access).filter_by(timeOut=None, location_id=g.admin.location_id)

	if 'warn' in request.form:
		in_lab = query.all()
		for user in in_lab: #type: User
			db.add(Warning(warner_id=g.admin.sid,
			               warnee_id=user.sid,
			               reason='Failed to tap out',
			               location_id=g.admin.location_id,
			               banned=False))

	query.update({"timeOut": sa.func.now()}, synchronize_session=False)
	db.commit()
	session['admin'] = None
	return redirect('/success/checkout')


@app.route('/admin/training/add', methods=['POST'])
def admin_add_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	t = []      #list of trainings to add
	#add all required
	if int(request.form['machine']) == (-1):
		required_list = db.query(Machine).filter_by(location_id = session['location_id']).filter_by(required = 1).all()
		for each in required_list:
			t.append(Training(trainee_id=int(request.form['student_id']),
	             trainer_id=int(session['admin']),
	             machine_id=each.id,
	             date=sa.func.now()))
	else:
		t.append(Training(trainee_id=int(request.form['student_id']),
	             trainer_id=int(session['admin']),
	             machine_id=int(request.form['machine']),
	             date=sa.func.now()))
	try:
		check_allowed_modify(session['admin'],request.form['student_id'],session['location_id'])
		db.add_all(t)
		db.commit()
		return redirect('/admin/lookup?sid=' + str(request.form['student_id']))
	except ProcessingError as error:
		return redirect("/admin/lookup?sid=" + str(request.form["student_id"]) + "&error=" + str(error))


@app.route('/admin/training/group_add', methods=['GET'])
def admin_group_add_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	machines = db.query(Machine).filter_by(location_id=g.admin.location_id).all()
	return render_template('admin/group_training.html', machines=machines)


@app.route('/admin/training/remove', methods=["POST"])
def admin_remove_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	training = db.query(Training).filter_by(id=request.form.get('id')).one_or_none()
	if training:
		try:
			sid = training.trainee_id if training else None
			check_allowed_modify(session['admin'], sid, session['location_id'])
			db.delete(training)
			db.commit()
		except ProcessingError as error:
			return redirect("/admin/lookup?sid=" + str(sid) + "&error=" + str(error))
		return redirect('/admin/lookup?sid=' + str(sid))
	else : return redirect('/internal_error.html')

# TODO: implement location & machine UI
@app.route('/admin/locations')
def admin_locations():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	locations = db.query(Location).all()

	return render_template("admin/locations.html", locations=locations)


@app.route('/admin/locations/<int:id>')
def admin_location(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	db = db_session()
	location = db.query(Location).get(id)
	machines = db.query(Machine).filter_by(location_id=id)
	staff = db.query(UserLocation) \
		.join(UserLocation.type) \
		.filter(UserLocation.location_id == id, Type.level > 0) \
		.order_by(Type.level.desc())
	kiosks = db.query(Kiosk).filter_by(location_id=id)

	return render_template("admin/location.html", location=location, machines=machines, staff=staff, kiosks=kiosks)


@app.route('/admin/locations/remove')
def admin_remove_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')


@app.route('/admin/locations/update')
def admin_update_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')


@app.route('/admin/locations/add', methods=['GET', 'POST'])
def admin_add_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	if request.method == 'GET':
		return render_template('admin/add_location.html')

	elif request.method == 'POST':
		db = db_session()

		loc = Location(name=request.form['name'])
		loc.set_secret(request.form['secret'])

		db.add(loc)

		db.commit()

		default_training = Machine(location_id=loc.id, name='General Safety Training')
		db.add(default_training)

		db.commit()

		return redirect('/admin/locations/' + str(loc.id))


@app.route('/admin/locations/set_secret/<int:id>', methods=['POST'])
def admin_set_location_secret(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	if g.admin.type.level < 90:
		return redirect('/admin')

	db = db_session()
	loc = db.query(Location).get(id)
	loc.set_secret(request.form['newsecret'])
	db.commit()

	return redirect('/admin/locations/' + str(id))


@app.route('/admin/locations/add_machine/<int:id>', methods=['GET', 'POST'])
def admin_add_machine(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	if g.admin.type.level < 90:
		return redirect('/admin')

	if request.method == 'GET':
		return render_template('admin/add_machine.html', location_id=id)

	db = db_session()
	machine = Machine(name=request.form['name'], location_id=id)
	db.add(machine)
	db.commit()

	return redirect('/admin/locations/' + str(id))


class ProcessingError(BaseException):
	def __init__(self, message):
		self.message = message


def check_set_type(userInfo, typeInfo):
	if not typeInfo:
		raise ProcessingError("Type does not exist.")
	if not userInfo:
		raise ProcessingError("User does not exist.")
	if g.admin.type.level <= typeInfo.level:
		raise ProcessingError("You don't have permission to set that type.")
	if userInfo.type.level >= g.admin.type.level:
		raise ProcessingError("You don't have permission to modify that user.")

def check_allowed_modify(modifingUser, modifiedUser, location_id):
	db = db_session()
	if (db.query(UserLocation).filter_by(sid=modifingUser).filter_by(location_id=location_id).one().type.level >= 90) or \
			((modifingUser != modifiedUser) and \
			 (db.query(UserLocation).filter_by(sid=modifingUser).filter_by(location_id=location_id).one().type.level \
			  > db.query(UserLocation).filter_by(sid=modifiedUser).filter_by(location_id=location_id).one().type.level)):
		return #check successful
	else:
		raise ProcessingError("You don't have permission to modify that user.")

def set_type(userID, typeID):
	db = db_session()
	type = db.query(Type).filter_by(id=typeID).one_or_none()
	user = db.query(UserLocation).filter_by(sid=userID, location_id=session['location_id']).one_or_none()
	check_set_type(user, type)
	user.type_id = typeID
	db.commit()


@app.route('/admin/type/set', methods=["POST"])
def admin_set_type():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	try:
		set_type(request.form["sid"], request.form["tid"])
	except ProcessingError as error:
		return redirect("/admin/lookup?sid=" + request.form["sid"] + "&error=" + error.message)

	return redirect('/admin/lookup?sid=' + request.form['sid'])


# Automatic announcer control
@app.route('/admin/announcer')
def admin_announcer():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	return render_template("admin/announcer.html")


@app.route('/admin/announcer/test', methods=["POST"])
def admin_announcer_test():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.test()
	return redirect('/admin/announcer')


@app.route('/admin/announcer/power_tool', methods=['POST'])
def admin_announcer_power_tool():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)

	if request.form.get('endtimesub'):
		timestr = request.form['endtime']
		h = int(timestr.split(':')[0])
		m = int(timestr.split(':')[1].split(' ')[0])
		am = timestr.split(':')[1].split(' ')[1] == 'AM'
		announcer.tools_prohibited(h, m, am)
		return redirect('/admin/announcer')
	# elif request.form.get('endminssub'):
	#	announcer.tools_prohibited_rel(int(request.form['endmins']))
	#	return redirect('/admin/announcer')
	else:
		return abort(500)


@app.route('/admin/announcer/cancel_power_tool', methods=["POST"])
def admin_announcer_cancel_power_tool():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.cancel_tools_prohibited()
	return redirect('/admin/announcer')


@app.route('/admin/announcer/evac', methods=['POST'])
def admin_announcer_evac():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	emergency = bool(request.form.get('emergency'))
	emergency_exit = bool(request.form.get('emergency_exit'))
	announcer.start_evac(emergency, emergency_exit)
	return redirect('/admin/announcer')


@app.route('/admin/announcer/cancel_evac', methods=["POST"])
def admin_announcer_cancel_evac():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.stop_evac()
	return redirect('/admin/announcer')


# Card tap flow
@app.route('/waiver', methods=['GET', "POST"])
def waiver():
	if request.method == "GET":
		db = db_session()
		user = db.query(UserLocation).filter_by(
			sid=request.form.get('sid'),
			location_id=session['location_id']
		).one_or_none()

		missing_trainings = Training.build_missing_trainings_string(user.get_missing_trainings(db))

		return render_template('waiver.html',
		                       sid=request.args.get('sid'),
		                       show_training_warning=missing_trainings)
	elif request.method == "POST" and request.form.get('agreed') == 'true':
		db = db_session()
		db.add(Access(
			sid=request.form.get('sid'),
			location_id=session['location_id'],
			timeIn=sa.func.now(),
			timeOut=None
		))
		user = db.query(UserLocation) \
			.filter_by(sid=request.form.get('sid'),
		               location_id=session['location_id']) \
			.one_or_none()
		if user:
			user.waiverSigned = sa.func.now()
		db.commit()
		update_kiosks(session['location_id'], except_hwid=session['hardware_id'])

		missing_trainings = Training.build_missing_trainings_string(user.get_missing_trainings(db))

		if missing_trainings:
			return redirect(url_for('.needs_training', name=user.name, trainings=missing_trainings))
		else:
			return redirect('/success/checkin')
	else:
		return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
	db = db_session()
	if request.method == 'GET':
		resp = None
		card_id = request.args.get('card_id')
		name = None
		sid = None
		# before we check ACaPS, let's see if they already have a record
		card = db.query(HawkCard).filter_by(card=card_id).one_or_none()
		if card:
			sid = card.sid
			if card.user:
				name = card.user.name

		if not name or not sid:
			# ping acaps if we couldn't find everything
			try:
				il = IITLookup(app.config['IITLOOKUPURL'], app.config['IITLOOKUPUSER'], app.config['IITLOOKUPPASS'])
				resp = il.nameIDByCard(card_id)
			except:
				print(sys.exc_info()[0])
			if resp:
				sid = resp['idnumber'][1:]
				name = "%s %s" % (resp['first_name'], resp['last_name'])
		return render_template('register.html',
		                       sid=sid or "",
		                       card_id=card_id,
		                       name=name or "")

	elif request.method == 'POST':
		if request.form['name'] == "" or int(request.form['sid']) < 20000000:
			return render_template('register.html', sid=request.form['sid'], card_id=request.form['card_id'],
			                       name=request.form['name'])

		existing_user = db.query(User).get(request.form['sid'])
		if not existing_user:
			existing_user = User(sid=request.form['sid'], name=request.form['name'].title())
			db.add(existing_user)

		existing_user_location = db.query(UserLocation).get((request.form['sid'], session['location_id']))
		if not existing_user_location:
			db.add(UserLocation(sid=request.form['sid'],
			                    type_id=default_type.id,
			                    waiverSigned=None,
			                    location_id=session['location_id']))

		# associate the hawkcard with the user that was either just created or already exists
		card = db.query(HawkCard).filter_by(card=request.form['card_id']).one_or_none()
		card.sid = request.form['sid']

		db.commit()
		return redirect(url_for('.waiver', sid=request.form['sid']))


@socketio.on('ping')
def ping(data):
	send('pong')

@socketio.on('check in')
def check_in(data):
	try:
		db = db_session()
		data['card'] = int(data['card'])
		data['facility'] = int(data['facility'])
		data['location'] = int(data['location'])

		# server_kiosk = db.query(Kiosk).filter_by(location_id=data['location'], hardware_id=data['hwid']).one_or_none()

		resp = ""

		# if server_kiosk.token.decode('utf-8') != data['token']:
		#    emit('err', {'hwid': session['hardware_id'], 'err': 'Token mismatch'})
		#    emit('go', {'to': '/deauth', 'hwid': session['hardware_id']})
		#    return "Token mismatch!"

		card = db.query(HawkCard).filter_by(card=data['card']).one_or_none()

		location = db.query(Location).filter_by(id=data['location']).one_or_none()

		if not location:
			resp = ("Location %d not found (from kiosk %d)" % (data['location'], data['hwid']))
			logging.getLogger('checkin.socket').warning(resp)
			print(resp)
			return resp

		# check to see if user is already signed in; if so sign them out
		if card:
			lastIn = db.query(Access) \
				.filter_by(location_id=location.id) \
				.filter_by(timeOut=None) \
				.filter_by(sid=card.sid) \
				.first()

			if lastIn:
				resp = ("User %s (card id %d) signed out at location %s (id %d, kiosk %d)" % (
					card.user.name, data['card'], location.name, location.id, data['hwid']
				))
				logging.getLogger('checkin.socket').info(resp)
				# sign user out and send to confirmation page
				lastIn.timeOut = sa.func.now()
				emit('go', {'to': url_for('.success', action='checkout', name=card.user.name), 'hwid': data['hwid']})
				update_kiosks(location.id, except_hwid=data['hwid'])
				db.commit()
				return

		# check fire code capacity
		in_lab = db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=session['location_id']) \
			.options(joinedload(Access.user)) \
			.all()
		total_count = len(in_lab)

		if location.capacity and total_count >= location.capacity:
			emit('go', {'to': url_for('.over_fire_capacity'), 'hwid': data['hwid']})
			return

		student_count = staff_count = 0
		for a in in_lab:  # type: Access
			if a.user.type.level > 0 and not a.hideStaff:
				staff_count += 1
			else:
				student_count += 1

		if not card:
			# check to see if they already have a record
			student = None
			sid = None

			try:
				# check ACaPS
				il = IITLookup(app.config['IITLOOKUPURL'], app.config['IITLOOKUPUSER'], app.config['IITLOOKUPPASS'])
				student = il.nameIDByCard(data['card'])
				sid = int(student['idnumber'].replace('A', ''))
			except Exception:
				print("ERROR: IIT Lookup is offline.")
			if not student:
				# user is new and isn't in IIT's database
				card = HawkCard(sid=None, card=data['card'])
				db.add(card)
				db.commit()
			elif db.query(User).get(sid):
				# user exists, has a new card
				card = HawkCard(sid=sid, card=data['card'])
				db.add(card)
				db.commit()
			else:
				# first time in lab
				resp = ("User for card id %d not found" % data['card'])
				card = HawkCard(sid=None, card=data['card'])
				db.add(card)
				db.commit()

			db.commit()

		userLocation = None
		if card and card.user:
			userLocation = db.query(UserLocation).filter_by(sid=card.sid, location_id=location.id).one_or_none()

		# check that:
		# - card doesn't exist, user never finished the form, or card belongs to a student
		# - staff ratio is set
		# - floor(ratio * staff) <= student_count
		# if true then lab is over capacity
		if (not userLocation or (userLocation.type.level == 0)) \
				and location.staff_ratio \
				and math.floor(location.staff_ratio * staff_count) <= student_count:
			emit('go', {'to': url_for('.over_staff_capacity'), 'hwid': data['hwid']})
			return

		if not card or not userLocation:
			# send to registration page
			emit('go', {'to': url_for('.register', card_id=data['card']), 'hwid': data['hwid']})

		else:
			# user is banned
			if userLocation.type.level < 0:
				resp = ("User %s (card id %d) tried to sign in at %s but is banned! (id %d, kiosk %d)" % (
					card.user.name, data['card'], location.name, location.id, data['hwid']
				))
				emit('go', {'to': url_for('.banned'), 'hwid': data['hwid']})


			# user signing in
			elif userLocation.waiverSigned:
				missing_trainings_list = card.user.location_specific(db, location.id).get_missing_trainings(db)
				missing_trainings = Training.build_missing_trainings_string(missing_trainings_list)

				resp = ("User %s (card id %d) is cleared for entry at location %s (id %d, kiosk %d)" % (
					card.user.name, data['card'], location.name, location.id, data['hwid']
				))
				# sign user in and send to confirmation page
				accessEntry = Access(sid=card.sid, timeIn=sa.func.now(), location_id=location.id)
				db.add(accessEntry)

				# if user has training or there is no training required, let 'em in
				if not missing_trainings_list:
					if userLocation.type.level > 0:
						emit('go', {'to': url_for('.success', action='checkin', name=card.user.name,
						                          show_hide_staff_button=True, sid=card.sid),
						            'hwid': data['hwid']})
					else:
						emit('go', {'to': url_for('.success', action='checkin', name=card.user.name), 'hwid': data['hwid']})

				else:
					resp += (' (Missing trainings: %s)' % missing_trainings)
					emit('go', {'to': url_for('.needs_training', name=card.user.name, trainings=missing_trainings), 'hwid': data['hwid']})

				update_kiosks(location.id, except_hwid=data['hwid'])

			# user needs to sign waiver
			else:
				resp = ("User %s (card id %d) needs to sign waiver at location %s (id %d, kiosk %d)" % (
					card.user.name, data['card'],
					location.name, location.id, data['hwid']
				))
				# present waiver page
				emit('go', {'to': url_for('.waiver', sid=card.sid), 'hwid': data['hwid']})

		logEntry = CardScan(card_id=data['card'], time=sa.func.now(), location_id=data['location'])
		db.add(logEntry)

		db.commit()
		logging.getLogger('checkin.socket').info(resp)
		return resp
	except Exception as e:
		app.logger.error(e, exc_info=True)
		emit('go', {'to': url_for('.display_error'), 'hwid': data['hwid']})
		return 'Internal error.'


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Idea Shop Check In App')
	# parser.add_argument('-p', '--port', help='set the port to bind on', type=int)
	parser.add_argument('-a', '--admin', help='invoke admin tools instead of starting the web app', action='store_true')
	parser.add_argument('-l', '--location', help='choose the location to operate on', type=int)
	parser.add_argument('-s', '--secret', help='set a location\'s secret', type=str)
	args = parser.parse_args()

	if args.admin:
		_db = db_session()
		location = _db.query(Location).filter_by(id=args.location).one_or_none()
		if not location:
			print('Location %d does not exist!' % args.location)
			exit(404)

		if args.secret:
			location.set_secret(args.secret)
			_db.commit()
			print('Secret for %s (%d) updated.' % (location.name, location.id))
			exit(0)
		else:
			print('Location %d: %s' % (location.name, location.id))
			exit(0)

	app.jinja_env.auto_reload = True
	app.config['TEMPLATES_AUTO_RELOAD'] = True
	sslInfo = {}
	if "SSLCERT" in app.config and "SSLKEY" in app.config:
		sslInfo = {"certfile": app.config["SSLCERT"], "keyfile": app.config["SSLKEY"]}

	socketio.run(app, host='0.0.0.0', **sslInfo)
