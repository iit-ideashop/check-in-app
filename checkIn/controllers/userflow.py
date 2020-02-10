import logging
import sqlalchemy as sa
from collections import defaultdict
from flask import Blueprint, session, render_template, request, redirect, g
from checkIn.model import Access

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
	from checkIn.checkIn import update_kiosks, before_request

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
			lastIn = db.query(Access).get(int(request.args['aid']))

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

	db.commit()

	# need to query again for active users now that it's changed
	before_request()
	update_kiosks(session['location_id'], except_hwid=session['hardware_id'])

	if 'next' in request.args:
		return redirect(request.args.get('next'))
	else:
		return success('checkout')
