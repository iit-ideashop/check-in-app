from typing import Union, Callable, Optional, List, Dict

from flask import Flask, request
from flask_socketio import Namespace, join_room, leave_room, emit
from sqlalchemy.orm import Session, joinedload
import sqlalchemy as sa

from checkIn.model import HasRemoveMethod, Kiosk, Location, Access, UserLocation, User, HawkCard, get_types, Type, Warning


class SocketV2Namespace(Namespace):
	def __init__(self, namespace: str, db_session: Union[Callable[[], Session], HasRemoveMethod], app: Flask):
		self.db_session: Union[Callable[[], Session], HasRemoveMethod] = db_session
		self.db: Session = db_session()
		self.app: Flask = app
		self.active_connections: Dict[str, Kiosk] = {}
		self.conn_hwids: Dict[int, str] = {}

		(self.ban_type, self.default_type) = get_types(self.db)

		super().__init__(namespace)

	def send_tap(self, hardware_id: int, card: HawkCard):
		"""
			Emits a tap event to the specified kiosk

			:param hardware_id: The hardware ID to emit the tap event to
			:param card: The tapped card
			:returns: Emits the following event:

		"""
		if hardware_id not in self.conn_hwids.keys():
			self.app.logger.warning('Attempted to send tap for kiosk %d but there was no kiosk!' % (hardware_id))
			return
		kiosk: Kiosk = self.active_connections[self.conn_hwids[hardware_id]]
		if card.user:
			userLocation: UserLocation = card.user.location_specific(self.db, kiosk.location_id)
			if userLocation:
				user: Optional[Dict] = userLocation.to_v2_dict(self.db)
			else:
				user: Optional[Dict] = card.user.to_v2_dict(self.db)
		else:
			# attempt IIT Lookup
			from checkIn.iitlookup import IITLookup
			il = IITLookup(self.app.config['IITLOOKUPURL'], self.app.config['IITLOOKUPUSER'], self.app.config['IITLOOKUPPASS'])
			resp = il.nameIDByCard(card.card)

			user: Optional[Dict] = {
				'source': 'acaps',
				'name': '%s %s' % (resp['first_name'], resp['last_name']),
				'sid': int(resp['idnumber'][1:])
			} if resp else None

		self.emit('tap', {
			'card': {
				'number': card.card,
				'facility': 2508,
			},
			'user': user
			# each kiosk is by default in a room with its own connection id
		}, room=self.conn_hwids[hardware_id])

	def deauthorize_kiosk(self, hardware_id: int, new_conn_id: str = None):
		if hardware_id in self.conn_hwids and self.conn_hwids[hardware_id] != new_conn_id:
			old_kiosk: Kiosk = self.active_connections[self.conn_hwids[hardware_id]]

			self.emit('auth_error', {
				'location_id': old_kiosk.location_id,
				'hardware_id': old_kiosk.hardware_id,
				'message': 'This hardware ID has been used at another kiosk. Please re-authorize this kiosk.'
			}, room=self.conn_hwids[hardware_id])

			conn_id: str = self.conn_hwids[hardware_id]
			del self.conn_hwids[hardware_id]
			del self.active_connections[conn_id]

	def get_users_list(self, location_id: int) -> List[Access]:
		return self.db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=location_id) \
			.options(joinedload(Access.user)) \
			.options(joinedload(Access.user, UserLocation.user)) \
			.options(joinedload(Access.user, UserLocation.type)) \
			.options(joinedload(Access.user, UserLocation.user, User.trainings)) \
			.all()

	def get_initial_app_state(self, location: Optional[Location], kiosk: Kiosk) -> Dict:
		if not location:
			location = kiosk.location

		in_lab: List[Access] = self.get_users_list(location.id)

		return {
			'location': {
				'hardwareId': kiosk.hardware_id,
				'locationId': location.id,
				'name': location.name,
				'token': kiosk.token,
				'capacity': location.capacity,
				'staffRatio': location.staff_ratio,
			},
			'labState': {
				'activeUsers': [u.user.to_v2_dict(self.db) for u in in_lab]
			}
		}

	def on_connect(self):
		self.app.logger.info('Client ' + request.sid + ' connected.')
		locations: List[Location] = self.db.query(Location).all()
		emit('location_list', {l.id: l.name for l in locations})

	def on_disconnect(self):
		self.app.logger.info('Client ' + request.sid + ' disconnected.')
		if request.sid in self.active_connections.keys():
			kiosk: Kiosk = self.active_connections[request.sid]
			del self.active_connections[request.sid]
			del self.conn_hwids[kiosk.hardware_id]
		pass

	def on_error(self, exc):
		emit('server_error', {
			'title': 'Server error',
			'message': 'An error has occurred. Please try again. If this continues, please contact a staff member.'
		})
		self.app.logger.error(exc, exc_info=True)

	def on_auth(self, data: Dict):
		"""
			Kiosk Authorization Event
			data: {location_id: int, hardware_id: int, secret: string}
			emits:
				on error:
					auth_error { location_id: int, hardware_id: int, message: string }
				on success:
					auth_success {
						initial_state: {
							location: {
								name: string, id: int, token: string
							},
							activeUsers: [{
								name: string, photo: string (url), type: { name: string, level: int },
								missingTrainings: bool, sid: int
							}]
						}
					}
			"""
		# check presented secret
		self.app.logger.info('Client ' + request.sid + ' requested authentication.')
		location: Optional[Location] = self.db.query(Location).get(data['location_id'])
		if not location:
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Invalid location!'
			})
			self.app.logger.info('Client ' + request.sid + ' denied authentication: invalid location')
			return
		if not location.verify_secret(data['secret']):
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Invalid secret!'
			})
			self.app.logger.info('Client ' + request.sid + ' denied authentication: invalid secret')
			return

		# create kiosk record in db
		kiosk: Kiosk = Kiosk(
			location_id=location.id,
			hardware_id=data['hardware_id'],
			last_seen=sa.func.now(),
			last_ip=request.remote_addr
		)

		kiosk.refresh_token()

		kiosk = self.db.merge(kiosk)

		self.deauthorize_kiosk(kiosk.hardware_id, request.sid)

		emit('auth_success', {
			'initial_state': self.get_initial_app_state(location, kiosk)
		})

		join_room('location-' + str(location.id))
		self.db.commit()

		self.conn_hwids[int(kiosk.hardware_id)] = request.sid
		self.active_connections[request.sid] = kiosk

		self.app.logger.info('Client ' + request.sid + ' successfully authenticated to ' + repr(location))

	def on_reauth(self, data: Dict):
		"""
			reauth event
			:data {location_id: int, hardware_id: int, token: string}
			:emits
				on error:
					auth_error { location_id: int, hardware_id: int, message: string }
				on success:
					auth_success {
						initial_state: {
							location: {
								name: string, id: int, token: string
							},
							activeUsers: [{
								name: string, photo: string (url), type: { name: string, level: int },
								missingTrainings: bool
							}]
						}
					}
		"""
		kiosk: Kiosk = self.db.query(Kiosk).options(joinedload(Kiosk.location)).get(data['hardware_id'])
		if kiosk and kiosk.location_id == data['location_id'] and kiosk.validate_token(data['token']):
			# kiosk.refresh_token()
			emit('auth_success', {
				'initial_state': self.get_initial_app_state(kiosk.location, kiosk)
			})
			join_room('location-' + str(kiosk.location.id))
			self.app.logger.info('Client ' + request.sid + ' successfully reauthenticated to ' + repr(kiosk.location))
		else:
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Cannot reauthenticate this kiosk. Please manually reauthenticate.'
			})
			self.app.logger.info('Client ' + request.sid + ' failed reauthentication to ' + repr(kiosk.location))
			return

		self.db.commit()

		# deauthorize the old kiosk
		self.deauthorize_kiosk(kiosk.hardware_id, request.sid)

		self.conn_hwids[int(kiosk.hardware_id)] = request.sid
		self.active_connections[request.sid] = kiosk

	def on_check_out(self, data):
		# we have 2 separate events here - check_in and check_out - in an attempt to allow kiosks to maintain a locally
		# consistent state. if the kiosk displays checking out but it's out of sync with the system, don't actually do
		# anything and have the user re-tap

		# auth code may need some refinement later on
		# TODO: make this a decorator
		if request.sid not in self.active_connections.keys() or self.active_connections[request.sid].token != data['location']['token']:
			emit('auth_error', {
				'location_id': data['location']['locationId'],
				'hardware_id': data['location']['hardwareId'],
				'message': 'This session is not authorized. Please re-authenticate the kiosk.'
			})
			return

		kiosk: Kiosk = self.active_connections[request.sid]

		access: List[Access] = self.db.query(Access).filter_by(sid=data['user']['sid'],
		                                                       location_id=kiosk.location_id,
		                                                       timeOut=None).all()
		for a in access:
			# just in case there are multiple records for some reason... weirder things have happened!
			a.timeOut = sa.func.now()

		# if we actually checked anyone out
		if len(access):
			user: Optional[UserLocation] = self.db.query(UserLocation).filter_by(sid=data['user']['sid'],
			                                                                     location_id=kiosk.location_id)\
																	  .one_or_none()
			if user:
				emit('user_leave', {
					'user': user.to_v2_dict(self.db)
				}, room='location-' + str(kiosk.location_id))

		else:
			# TODO: resync client because something got fucked
			return

		self.db.commit()

	def on_check_in(self, data):
		if request.sid not in self.active_connections.keys() or self.active_connections[request.sid].token != data['location']['token']:
			emit('auth_error', {
				'location_id': data['location']['locationId'],
				'hardware_id': data['location']['hardwareId'],
				'message': 'This session is not authorized. Please re-authenticate the kiosk.'
			})
			return

		kiosk: Kiosk = self.active_connections[request.sid]

		# check for existing session, if found don't create a new one
		access: int = self.db.query(Access.id).filter_by(sid=data['user']['sid'],
	 	                                                 location_id=kiosk.location_id,
	                                                     timeOut=None).scalar()
		if access:
			# TODO: resync client because something got fucked
			return

		# check to see if user exists
		user: Optional[User] = self.db.query(User).filter_by(sid=data['user']['sid']).one_or_none()
		if not user:
			emit('check_in_result', {
				'user': user.to_v2_dict(self.db),
				'result': 'requireRegister'
			})
			return

		# check to see if user has a location specific record
		userLocation: Optional[UserLocation] = user.location_specific(self.db, kiosk.location_id)
		if not userLocation or userLocation.waiverSigned is None:
			# if not, show waiver
			userLocation = UserLocation(sid=user.sid, location_id=kiosk.location_id, type_id=self.default_type.id)
			self.db.add(userLocation)
			emit('check_in_result', {
				'user': user.to_v2_dict(self.db),
				'result': 'requireWaiver'
			})
			return

		# check to see if user was banned
		banned: int = self.db.query(Warning.id).filter(Warning.location_id == kiosk.location_id,
		                                               Warning.warnee_id == userLocation.sid,
		                                               Warning.banned).scalar()
		if userLocation.type.id == self.ban_type.id or banned:
			emit('check_in_result', {
				'user': user.to_v2_dict(self.db),
				'result': 'banned'
			})
			return

		# capacity checking is handled clientside, but we should verify it just in case
		if userLocation.type.level <= 0:
			userQuery: sa.orm.Query = self.db.query(Access).filter_by(location_id=kiosk.location_id, timeOut=None).subquery()
			userCount: int = self.db.query(userQuery).filter(Access.user.has(UserLocation.type.has(Type.level <= 0))).count()
			if userCount + 1 > kiosk.location.capacity:
				emit('check_in_result', {
					'user': user.to_v2_dict(self.db),
					'result': 'deniedFireCapacity'
				})
				return

			staffCount: int = self.db.query(userQuery).filter(Access.user.has(UserLocation.type.has(Type.level > 0))).count()
			if userCount + 1 > staffCount * kiosk.location.staff_ratio:
				emit('check_in_result', {
					'user': user.to_v2_dict(self.db),
					'result': 'deniedStaffRatio'
				})
				return

		# no need to check safety trainings, someone without trainings won't be denied entry
		# displaying that is already handled client side and that data is sent on every tap

		# create an access record
		access: Access = Access(timeIn=sa.func.now, sid=userLocation.sid, location_id=kiosk.location_id)
		self.db.add(access)

		# respond to request
		emit('check_in_result', {
			'user': user.to_v2_dict(self.db),
			'result': 'enter'
		})

		# broadcast to room
		emit('user_enter', {
			'user': userLocation.to_v2_dict(self.db)
		}, room='location-' + str(kiosk.location_id))

		self.db.commit()


