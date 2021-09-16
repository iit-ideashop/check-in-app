import logging
from flask import Blueprint, request, abort, g, session, jsonify
from checkIn.model import HawkCard, Kiosk, Access
from sqlalchemy.orm import joinedload

api_controller = Blueprint('api', __name__)


@api_controller.route('/card_read/<int:hwid>', methods=['POST'])
def card_read(hwid):
	resp = 'Read success from HWID %d: Facility %s, card %s' % (hwid, request.form['facility'], request.form['cardnum'])
	kiosk = g.db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard = g.db.query(HawkCard).filter_by(card=request.form['cardnum'],
	                                        facility=request.form['facility']).one_or_none()
	user = dbcard.user if dbcard else None
	g.socketio.emit('scan', {
		'facility': request.form['facility'],
		'card': request.form['cardnum'],
		'hwid': hwid,
		'sid': user.sid if user else None,
		'name': user.name if user else None,
	})
	logging.getLogger('checkin.card').info(resp)
	return resp


@api_controller.route('/anumber_read/<int:hwid>', methods=['GET'])
def anumber_read(hwid):
	card = g.db.query(HawkCard).filter_by(sid=request.args['anumber'][1:]).first()
	print(card)
	resp = 'Read success from HWID %d: Facility %s, card %s' % (hwid, "null", card.card)
	kiosk = g.db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard = g.db.query(HawkCard).filter_by(card=card.card).one_or_none()
	user = dbcard.user if dbcard else None
	g.socketio.emit('scan', {
		'facility': '2508',
		'card': card.card,
		'hwid': hwid,
		'sid': user.sid if user else None,
		'name': user.name if user else None,
	})
	logging.getLogger('checkin.card').info(resp)
	return resp


@api_controller.route('/api/in_lab')
def in_lab():
	in_lab = g.db.query(Access) \
		.filter_by(timeOut=None) \
		.filter_by(location_id=session['location_id']) \
		.options(joinedload(Access.user)) \
		.all() \
		if 'location_id' in session else list()
	students = [a.user for a in in_lab if a.hideStaff or a.user.type.level <= 0]
	staff = [a.user for a in in_lab if not a.hideStaff and a.user.type.level > 0]
	staff.sort(key=lambda x: x.type.level, reverse=True)
	for student in students:
		if not student.get_missing_trainings(g.db):
			student.general_training = True
		else:
			student.general_training = False
	return jsonify({'staff': [{'name': each.name, 'photo': each.photo, 'type': each.type.name} for each in staff],
	                'students': [{'name': each.name, 'valid': each.general_training} for each in students]})
