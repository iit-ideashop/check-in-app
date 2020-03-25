import logging
from typing import Optional

from flask import Blueprint, request, abort, g
from checkIn.model import HawkCard, Kiosk

api_controller = Blueprint('api', __name__)


@api_controller.route('/card_read/<int:hwid>', methods=['POST'])
def card_read(hwid):
	resp: str = 'Read success from HWID %d: Facility %s, card %s' % (hwid, request.form['facility'], request.form['cardnum'])
	kiosk: Optional[Kiosk] = g.db.query(Kiosk).filter_by(hardware_id=hwid).one_or_none()
	if not kiosk:
		return abort(403)

	dbcard: HawkCard = g.db.query(HawkCard).filter_by(card=request.form['cardnum']).one_or_none()
	if not dbcard:
		dbcard = HawkCard(card=request.form['cardnum'])

	g.socketio.emit('scan', {
		'facility': request.form['facility'],
		'card': dbcard.card,
		'hwid': hwid,
		'sid': dbcard.user.sid if dbcard.user else None,
		'name': dbcard.user.name if dbcard.user else None,
	})

	# v2 emit
	g.io_controller_v2.send_tap(hwid, dbcard)

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

	# v2 emit
	g.io_controller_v2.send_tap(hwid, card)

	logging.getLogger('checkin.card').info(resp)
	return resp