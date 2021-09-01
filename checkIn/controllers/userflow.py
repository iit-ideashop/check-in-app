import logging
import sys

import sqlalchemy as sa
from collections import defaultdict
from flask import Blueprint, session, render_template, request, redirect, g, url_for, current_app
from checkIn.iitlookup import IITLookup
from checkIn.model import Access, UserLocation, Training, HawkCard, User

userflow_controller = Blueprint('userflow', __name__)

success_messages = defaultdict(tuple)
success_messages.update({
	'login': ("Logged in", "glyphicon-ok"),
	'logout': ("Logged out", "glyphicon-remove"),
	'checkin': ("Welcome", "glyphicon-log-in"),
	'checkout': ("Goodbye", "glyphicon-log-out")
})


@userflow_controller.route('/success/<action>', methods=['GET'])
def success(action):
	return render_template('success.html', msg=success_messages[action],
	                       show_hide_staff_button=request.args.get('show_hide_staff_button', False),
	                       sid=request.args.get('sid', 0))


@userflow_controller.route('/banned', methods=['GET'])
def banned():
	return render_template('banned.html')


@userflow_controller.route('/over_fire_capacity', methods=['GET'])
def over_fire_capacity():
	return render_template('over_fire_capacity.html')


@userflow_controller.route('/over_staff_capacity', methods=['GET'])
def over_staff_capacity():
	return render_template('over_staff_capacity.html')


@userflow_controller.route('/needs_training', methods=['GET'])
def needs_training():
	return render_template('needs_training.html')


@userflow_controller.route('/')
def root():
	if 'admin' in session:
		del session['admin']

	return render_template('index.html')


@userflow_controller.route('/index', methods=['GET'])
def index():
	return redirect('/')


@userflow_controller.route('/checkout', methods=['POST'])
def checkout():
	from checkIn.checkIn import before_request

	if not g.location:
		logging.getLogger('checkin.checkout').warning("Location %d not found (from kiosk %d)" % (session['location_id'], session['hardware_id']))

	else:
		lastIn = None
		if 'sid' in request.args:
			lastIn = g.db.query(Access) \
				.filter_by(location_id=g.location.id) \
				.filter_by(timeOut=None) \
				.filter_by(sid=int(request.args['sid'])) \
				.first()
		elif 'aid' in request.args:
			lastIn = g.db.query(Access).get(int(request.args['aid']))

		if lastIn:
			# user signing out
			logging.getLogger('checkin.checkout').info("User %s signed out manually at location %s (id %d, kiosk %d)" % (
				lastIn.user.name, g.location.name, g.location.id, session['hardware_id']
			))
			# sign user out and send to confirmation page
			lastIn.timeOut = sa.func.now()

			# assign a warning if we need to
			if g.admin and 'warn' in request.form:
				Warning.warn(g.db, warner=g.admin.sid, warnee=lastIn.sid, reason="Failed to tap out", location=lastIn.location_id, banned=False)

	g.db.commit()

	# need to query again for active users now that it's changed
	before_request()
	g.io_controller.update_kiosks(session['location_id'], except_hwid=session['hardware_id'])

	if 'next' in request.args:
		return redirect(request.args.get('next'))
	else:
		return success('checkout')


# Card tap flow
@userflow_controller.route('/waiver', methods=['GET', "POST"])
def waiver():
	if request.method == "GET":
		return render_template('waiver.html',
		                       sid=request.args.get('sid'))
	elif request.method == "POST" and request.form.get('agreed') == 'true':
		g.db.add(Access(
			sid=request.form.get('sid'),
			location_id=session['location_id'],
			timeIn=sa.func.now(),
			timeOut=None
		))
		user = g.db.query(UserLocation) \
			.filter_by(sid=request.form.get('sid'),
		               location_id=session['location_id']) \
			.one_or_none()
		if user:
			user.waiverSigned = sa.func.now()
		g.db.commit()
		g.io_controller.update_kiosks(session['location_id'], except_hwid=session['hardware_id'])

		missing_trainings = Training.build_missing_trainings_string(user.get_missing_trainings(g.db))

		if missing_trainings:
			return redirect(url_for('userflow.needs_training', name=user.name, trainings=missing_trainings))
		else:
			return redirect('/success/checkin')
	else:
		return redirect('/')


@userflow_controller.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'GET':
		resp = None
		card_id = request.args.get('card_id')
		name = None
		sid = None
		# before we check ACaPS, let's see if they already have a record
		card = g.db.query(HawkCard).filter_by(card=card_id).one_or_none()
		if card:
			sid = card.sid
			if card.user:
				name = card.user.name

		if not name or not sid:
			# ping acaps if we couldn't find everything
			try:
				il = IITLookup(current_app.config['IITLOOKUPURL'], current_app.config['IITLOOKUPUSER'], current_app.config['IITLOOKUPPASS'])
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

		existing_user = g.db.query(User).get(request.form['sid'])
		if not existing_user:
			existing_user = User(sid=request.form['sid'], name=request.form['name'].title())
			g.db.add(existing_user)

		existing_user_location = g.db.query(UserLocation).get((request.form['sid'], session['location_id']))
		if not existing_user_location:
			from checkIn.model import default_type
			g.db.add(UserLocation(sid=request.form['sid'],
			                    type_id=default_type.id,
			                    waiverSigned=None,
			                    location_id=session['location_id']))

		# associate the hawkcard with the user that was either just created or already exists
		card = g.db.query(HawkCard).filter_by(card=request.form['card_id']).one_or_none()
		card.sid = request.form['sid']

		g.db.commit()
		return redirect(url_for('userflow.waiver', sid=request.form['sid']))