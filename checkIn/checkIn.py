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
from datetime import datetime
from typing import Optional, Tuple, List
from checkIn.iitlookup import IITLookup
from checkIn.model import User, UserLocation, Type, Training, Machine, Access, CardScan, Kiosk, Location, HawkCard, \
	Warning, init_db, get_types
from checkIn.controllers.auth import auth_controller
from checkIn.controllers.userflow import userflow_controller
from checkIn.controllers.api import api_controller

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
	db = db_session()
	g.socketio = socketio
	g.db = db

	if 'location_id' not in session \
			and request.endpoint != 'auth.auth' \
			and request.endpoint != 'api.card_read' \
			and request.endpoint != '/error' \
			and str(request.path[0:7]) != '/static':
		return redirect(url_for('auth.auth'))

	if request.endpoint and request.endpoint != 'api.card_read' and \
			'socket.io' not in request.path and \
			'static' not in request.path and \
			'/auth' not in request.path:
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


app.register_blueprint(auth_controller)
app.register_blueprint(userflow_controller)
app.register_blueprint(api_controller)


# Card tap flow
@app.route('/waiver', methods=['GET', "POST"])
def waiver():
	if request.method == "GET":
		db = db_session()

		return render_template('waiver.html',
		                       sid=request.args.get('sid'))
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
			return redirect(url_for('userflow.needs_training', name=user.name, trainings=missing_trainings))
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
				emit('go', {'to': url_for('userflow.success', action='checkout', name=card.user.name), 'hwid': data['hwid']})
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
			emit('go', {'to': url_for('userflow.over_fire_capacity'), 'hwid': data['hwid']})
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
			emit('go', {'to': url_for('userflow.over_staff_capacity'), 'hwid': data['hwid']})
			return

		if not card or not userLocation:
			# send to registration page
			emit('go', {'to': url_for('userflow.register', card_id=data['card']), 'hwid': data['hwid']})

		else:
			# user is banned
			if userLocation.type.level < 0:
				resp = ("User %s (card id %d) tried to sign in at %s but is banned! (id %d, kiosk %d)" % (
					card.user.name, data['card'], location.name, location.id, data['hwid']
				))
				emit('go', {'to': url_for('userflow.banned'), 'hwid': data['hwid']})


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
						emit('go', {'to': url_for('userflow.success', action='checkin', name=card.user.name,
						                          show_hide_staff_button=True, sid=card.sid),
						            'hwid': data['hwid']})
					else:
						emit('go', {'to': url_for('userflow.success', action='checkin', name=card.user.name), 'hwid': data['hwid']})

				else:
					resp += (' (Missing trainings: %s)' % missing_trainings)
					emit('go', {'to': url_for('userflow.needs_training', name=card.user.name, trainings=missing_trainings), 'hwid': data['hwid']})

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
