import math
from typing import Optional

from flask import url_for, session, logging, g
from flask_socketio import Namespace, emit, send

import sqlalchemy as sa
from sqlalchemy.orm import joinedload

from checkIn.model import HawkCard, Location, Access, UserLocation, User, CardScan, Training, Kiosk
from iitlookup import IITLookup


class SocketV1Namespace(Namespace):
	def __init__(self, namespace, db_session, app):
		self.db_session = db_session
		self.app = app
		super().__init__(namespace)

	def on_connect(self):
		pass

	def on_disconnect(self):
		pass

	def on_ping(self, data):
		send('pong')

	def on_check_in(self, data):
		try:
			db = self.db_session()
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
				self.app.logger.warning(resp)
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
					self.app.logger.info(resp)
					# sign user out and send to confirmation page
					lastIn.timeOut = sa.func.now()
					emit('go', {'to': url_for('userflow.success', action='checkout', name=card.user.name),
					            'hwid': data['hwid']})
					self.update_kiosks(location.id, except_hwid=data['hwid'], use_request_context=False)

					# for v2 api
					self.emit('user_leave', {'user': lastIn.user.to_v2_dict(db)}, namespace='/v2', room='location-' + str(location.id))

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
					il = IITLookup(self.app.config['IITLOOKUPURL'], self.app.config['IITLOOKUPUSER'], self.app.config['IITLOOKUPPASS'])
					student = il.nameIDByCard(data['card'])
					sid = int(student['idnumber'].replace('A', ''))
				except Exception:
					self.app.logger.error("ERROR: IIT Lookup is offline.")
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
							emit('go', {'to': url_for('userflow.success', action='checkin', name=card.user.name),
							            'hwid': data['hwid']})

					else:
						resp += (' (Missing trainings: %s)' % missing_trainings)
						emit('go', {
							'to': url_for('userflow.needs_training', name=card.user.name, trainings=missing_trainings),
							'hwid': data['hwid']})

					self.update_kiosks(location.id, except_hwid=data['hwid'], use_request_context=False)

					# for v2 api
					self.emit('user_enter', {'user': userLocation.to_v2_dict(db)},
					          namespace='/v2', room='location-' + str(location.id))

				# user needs to sign waiver
				else:
					resp = ("User %s (card id %d) needs to sign waiver at location %s (id %d, kiosk %d)" % (
						card.user.name, data['card'],
						location.name, location.id, data['hwid']
					))
					# present waiver page
					emit('go', {'to': url_for('userflow.waiver', sid=card.sid), 'hwid': data['hwid']})

			logEntry = CardScan(card_id=data['card'], time=sa.func.now(), location_id=data['location'])
			db.add(logEntry)

			db.commit()
			self.app.logger.info(resp)
			return resp
		except Exception as e:
			self.app.logger.error(e, exc_info=True)
			emit('go', {'to': url_for('.display_error'), 'hwid': data['hwid']})
			return 'Internal error.'

	def update_kiosks(self, location, except_hwid=None, use_request_context=True):
		db = self.db_session()
		kiosks = db.query(Kiosk).filter_by(location_id=location)
		if except_hwid:
			kiosks = kiosks.filter(Kiosk.hardware_id != except_hwid)
		kiosks = kiosks.all()
		for kiosk in kiosks:
			if use_request_context:
				g.socketio.emit('go', {'to': '/', 'hwid': kiosk.hardware_id})
			else:
				emit('go', {'to': '/', 'hwid': kiosk.hardware_id})


io_controller = None