from datetime import datetime

import sqlalchemy as sa
from typing import Optional, List, Tuple
from flask import Blueprint, render_template, redirect, g, session, request, url_for
from checkIn.model import Access, UserLocation, User, ban_type, HawkCard, Machine, Type, Warning, Training, Location, \
	Kiosk

admin_controller = Blueprint('admin', __name__)


@admin_controller.route('/admin', methods=['GET'])
def admin_dash():
	if g.admin and g.admin.location_id == session['location_id']:
		return render_template('admin/index.html')
	else:
		return redirect('/')


@admin_controller.route('/admin/hideStaff', methods=['POST'])
def admin_hide_staff():
	access = g.db.query(Access).filter_by(sid=request.form.get('sid'), location_id=session['location_id'], timeOut=None) \
		.one_or_none()
	access.hideStaff = not access.hideStaff
	g.db.commit()
	return redirect('/')


# Admin authentication
@admin_controller.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
	if request.method == "GET":
		return render_template('admin/login_cardtap.html')
	else:
		if not request.form.get('sid') or not request.form.get('sid').isdigit():
			return render_template('admin/login_cardtap.html',
			                       error='This HawkCard is not registered!')

		# check to see if user has a pin
		user = g.db.query(UserLocation).filter_by(sid=request.form.get('sid'), location_id=session['location_id']).one_or_none()

		if not user.pin and user.type.level > 0:
			session['admin'] = user.sid
			return render_template('admin/change_pin.html')
		elif user.type.level <= 0:
			return render_template('admin/login_cardtap.html',
			                       error='Insufficient permission! This incident will be reported.')

		return render_template('admin/login_pin.html',
		                       sid=request.form.get('sid'))


@admin_controller.route('/admin/auth', methods=['POST'])
def admin_auth():
	# sanity checks
	# check for sufficient permission
	user = g.db.query(UserLocation).filter_by(sid=request.form['sid'], location_id=session['location_id']).one_or_none()
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


@admin_controller.route('/admin/logout', methods=['POST'])
def admin_logout():
	session['admin'] = None
	return redirect(url_for('userflow.success', action='logout'))


@admin_controller.route('/admin/change_pin', methods=['GET', 'POST'])
def admin_change_pin():
	if request.method == 'GET':
		return render_template('admin/change_pin.html')
	else:
		# validate pin
		if request.form['pin'] == '' or request.form['pin'] is None:
			return render_template('admin/change_pin.html', error='Your PIN can not be empty!')

		user = g.db.query(User).filter_by(sid=session['admin']).one_or_none()
		user.set_pin(request.form['pin'])
		g.db.commit()
		return redirect('/admin')


# Admin flow
@admin_controller.route('/admin/warnings/<int:sid>', methods=["GET", "POST"])
def admin_warn(sid):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	warnee = g.db.query(UserLocation).filter_by(sid=sid, location_id=g.admin.location_id).one_or_none()
	warnings = g.db.query(Warning).filter_by(warnee_id=sid).order_by(sa.desc(Warning.time)).all()

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

	warning = Warning.warn(g.db, warner=g.admin.sid, warnee=sid, location=session["location_id"], reason=reason, comments=comments, banned=shouldBan)
	g.db.commit()
	return render_template('admin/warnings.html', warnee=warnee, warnings=[warning] + warnings, canBan=canBan, admin=g.admin)


def lookupQuery(location_id: int, sid: Optional[int], name: Optional[str], card_no: Optional[int]) -> List[Tuple[UserLocation, int]]:
	warningCounts = g.db.query(
		Warning.warnee_id,
		sa.func.count(Warning.warnee_id).label("warningCount")
	).group_by(Warning.warnee_id).subquery("warningCounts")
	query = g.db.query(
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


@admin_controller.route('/admin/lookup', methods=['GET'])
def admin_lookup():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	sid = request.args.get('sid')
	try:
		sid = int(sid)
	except (TypeError, ValueError):
		sid = None
	name = request.args.get('name')
	card_id = request.args.get('card')
	try:
		card_id = int(card_id)
	except (TypeError, ValueError):
		card_id = None

	location_id = request.args.get('location') if 'location' in request.args else session['location_id']

	access_log = None
	machines = None
	types = None

	results = lookupQuery(location_id, sid, name, card_id)

	if len(results) == 1:
		machines = g.db.query(Machine).filter_by(location_id=session['location_id']).all()
		# if found user has lower rank than admin user
		if results[0][0].type.level < g.admin.type.level:
			types = g.db.query(Type).filter(Type.level <= g.admin.type.level).all()
		access_log = g.db.query(Access) \
			.filter_by(sid=results[0][0].sid, location_id=session['location_id']) \
			.order_by(Access.timeIn.desc()).limit(10).all()

	return render_template('admin/lookup.html', results=results, machines=machines, types=types, access_log=access_log,
	                       now=datetime.now(), error=request.args.get('error'))


@admin_controller.route('/admin/clear_waiver', methods=['POST'])
def admin_clear_waiver():
	if not session['admin']:
		return redirect('/')
	if not request.form.get('sid'):
		return redirect('/admin/lookup')

	user = g.db.query(UserLocation).filter_by(sid=request.form.get('sid'),
	                                        location_id=session['location_id']).one_or_none()
	user.waiverSigned = None
	g.db.commit()
	return redirect('/admin/lookup?sid=' + str(user.sid))


@admin_controller.route('/admin/clear_lab', methods=['POST'])
def admin_clear_lab():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/admin/login')

	query = g.db.query(Access).filter_by(timeOut=None, location_id=g.admin.location_id)

	if 'warn' in request.form:
		in_lab = query.all()
		for user in in_lab: #type: User
			g.db.add(Warning(warner_id=g.admin.sid,
			               warnee_id=user.sid,
			               reason='Failed to tap out',
			               location_id=g.admin.location_id,
			               banned=False))

	query.update({"timeOut": sa.func.now()}, synchronize_session=False)
	g.db.commit()
	session['admin'] = None
	return redirect('/success/checkout')


@admin_controller.route('/admin/training/add', methods=['POST'])
def admin_add_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	t = []      #list of trainings to add
	#add all required
	if int(request.form['machine']) == (-1):
		required_list = g.db.query(Machine).filter_by(location_id=session['location_id'], required=1).all()
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
		g.db.add_all(t)
		g.db.commit()
		return redirect('/admin/lookup?sid=' + str(request.form['student_id']))
	except ProcessingError as error:
		return redirect('/admin/lookup?sid=' + str(request.form['student_id']) + '&error=' + str(error))


@admin_controller.route('/admin/training/group_add', methods=['GET'])
def admin_group_add_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	machines = g.db.query(Machine).filter_by(location_id=g.admin.location_id).all()
	return render_template('admin/group_training.html', machines=machines)


@admin_controller.route('/admin/training/remove', methods=["POST"])
def admin_remove_training():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	training = g.db.query(Training).filter_by(id=request.form.get('id')).one_or_none()
	if training:
		try:
			sid = training.trainee_id if training else None
			check_allowed_modify(session['admin'], sid, session['location_id'])
			g.db.delete(training)
			g.db.commit()
		except ProcessingError as error:
			return redirect("/admin/lookup?sid=" + str(sid) + "&error=" + str(error))
		return redirect('/admin/lookup?sid=' + str(sid))
	else:
		return redirect('/internal_error.html')

# TODO: implement location & machine UI
@admin_controller.route('/admin/locations')
def admin_locations():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	locations = g.db.query(Location).all()

	return render_template("admin/locations.html", locations=locations)


@admin_controller.route('/admin/locations/<int:id>')
def admin_location(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	location = g.db.query(Location).get(id)
	machines = g.db.query(Machine).filter_by(location_id=id)
	staff = g.db.query(UserLocation) \
		.join(UserLocation.type) \
		.filter(UserLocation.location_id == id, Type.level > 0) \
		.order_by(Type.level.desc())
	kiosks = g.db.query(Kiosk).filter_by(location_id=id)

	return render_template("admin/location.html", location=location, machines=machines, staff=staff, kiosks=kiosks)


@admin_controller.route('/admin/locations/remove')
def admin_remove_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')


@admin_controller.route('/admin/locations/update')
def admin_update_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')


@admin_controller.route('/admin/locations/add', methods=['GET', 'POST'])
def admin_add_location():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	if request.method == 'GET':
		return render_template('admin/add_location.html')

	elif request.method == 'POST':
		loc = Location(name=request.form['name'])
		loc.set_secret(request.form['secret'])

		g.db.add(loc)

		g.db.commit()

		default_training = Machine(location_id=loc.id, name='General Safety Training')
		g.db.add(default_training)

		g.db.commit()

		return redirect('/admin/locations/' + str(loc.id))


@admin_controller.route('/admin/locations/set_secret/<int:id>', methods=['POST'])
def admin_set_location_secret(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	if g.admin.type.level < 90:
		return redirect('/admin')

	loc = g.db.query(Location).get(id)
	loc.set_secret(request.form['newsecret'])
	g.db.commit()

	return redirect('/admin/locations/' + str(id))


@admin_controller.route('/admin/locations/add_machine/<int:id>', methods=['GET', 'POST'])
def admin_add_machine(id):
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	if g.admin.type.level < 90:
		return redirect('/admin')

	if request.method == 'GET':
		return render_template('admin/add_machine.html', location_id=id)

	machine = Machine(name=request.form['name'], location_id=id)
	g.db.add(machine)
	g.db.commit()

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
	if (g.db.query(UserLocation).filter_by(sid=modifingUser).filter_by(location_id=location_id).one().type.level >= 90) or \
			((modifingUser != modifiedUser) and \
			 (g.db.query(UserLocation).filter_by(sid=modifingUser).filter_by(location_id=location_id).one().type.level \
			  > g.db.query(UserLocation).filter_by(sid=modifiedUser).filter_by(location_id=location_id).one().type.level)):
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


@admin_controller.route('/admin/type/set', methods=["POST"])
def admin_set_type():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')

	try:
		set_type(request.form["sid"], request.form["tid"])
	except ProcessingError as error:
		return redirect("/admin/lookup?sid=" + request.form["sid"] + "&error=" + error.message)

	return redirect('/admin/lookup?sid=' + request.form['sid'])


# Automatic announcer control
@admin_controller.route('/admin/announcer')
def admin_announcer():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	return render_template("admin/announcer.html")


@admin_controller.route('/admin/announcer/test', methods=["POST"])
def admin_announcer_test():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.test()
	return redirect('/admin/announcer')


@admin_controller.route('/admin/announcer/power_tool', methods=['POST'])
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


@admin_controller.route('/admin/announcer/cancel_power_tool', methods=["POST"])
def admin_announcer_cancel_power_tool():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.cancel_tools_prohibited()
	return redirect('/admin/announcer')


@admin_controller.route('/admin/announcer/evac', methods=['POST'])
def admin_announcer_evac():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	emergency = bool(request.form.get('emergency'))
	emergency_exit = bool(request.form.get('emergency_exit'))
	announcer.start_evac(emergency, emergency_exit)
	return redirect('/admin/announcer')


@admin_controller.route('/admin/announcer/cancel_evac', methods=["POST"])
def admin_announcer_cancel_evac():
	if not g.admin or g.admin.location_id != session['location_id']:
		return redirect('/')
	announcer = zerorpc.Client()
	announcer.connect(g.location.announcer)
	announcer.stop_evac()
	return redirect('/admin/announcer')