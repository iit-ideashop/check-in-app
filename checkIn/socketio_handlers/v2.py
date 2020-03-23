from typing import Union, Callable, Optional, List, Dict

from flask import Flask, request
from flask_socketio import Namespace, join_room, leave_room, emit
from sqlalchemy.orm import Session, joinedload
import sqlalchemy as sa

from checkIn.model import HasRemoveMethod, Kiosk, Location, Access, UserLocation, User


class SocketV2Namespace(Namespace):
	def __init__(self, namespace: str, db_session: Union[Callable[[], Session], HasRemoveMethod], app: Flask):
		self.db_session: Union[Callable[[], Session], HasRemoveMethod] = db_session
		self.db: Session = db_session()
		self.app: Flask = app
		super().__init__(namespace)

	def get_users_list(self, location_id: int) -> List[UserLocation]:
		return self.db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=location_id) \
			.options(joinedload(Access.user)) \
			.options(joinedload(UserLocation.user)) \
			.options(joinedload(UserLocation.type)) \
			.options(joinedload(User.trainings)) \
			.all()

	def get_initial_app_state(self, location: Optional[Location], kiosk: Kiosk) -> Dict:
		if not location:
			location = kiosk.location

		in_lab = self.get_users_list(location.id)

		return {
			'location': {
				'name': location.name,
				'id': location.id,
				'token': kiosk.token
			},
			'activeUsers': [
				{
					'name': u.name,
					'photo': u.photo,
					'type': {
						'name': u.type.name,
						'level': u.type.level
					},
					'missingTrainings': bool(u.get_missing_trainings(self.db))
				} for u in in_lab
			]
		}

	def on_connect(self):
		pass

	def on_disconnect(self):
		pass

	def on_error(self, exc):
		emit('server_error', {
			'title': 'Server error',
			'message': 'An error has occurred. Please try again. If this continues, please contact a staff member.'
		})
		self.app.logger.error(exc, exc_info=True)

	"""
	auth event
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
						missingTrainings: bool
					}] 
				}
			}
	"""
	def on_auth(self, data: Dict):
		# check presented secret
		location: Optional[Location] = self.db.query(Location).get(data['location_id'])
		if not location:
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Invalid location!'
			})
			return
		if not location.verify_secret(data['secret']):
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Invalid secret!'
			})
			return

		# create kiosk record in db
		kiosk: Kiosk = Kiosk(
			location_id=location.id,
			hardware_id=data['hardware_id'],
			last_seen=sa.func.now(),
			last_ip=request.remote_addr
		)

		kiosk.refresh_token()

		self.db.merge(kiosk)

		emit('auth_success', {
			'initial_state': self.get_initial_app_state(location, kiosk)
		})

		join_room('location-' + str(location.id))
		self.db.commit()

	"""
	reauth event:
	"""
	def on_reauth(self, data: Dict):
		kiosk: Kiosk = self.db.query(Kiosk).options(joinedload(Kiosk.location)).get(data['hardware_id'])
		if kiosk and kiosk.location_id == data['location_id'] and kiosk.validate_token(data['token']):
			kiosk.refresh_token()
			emit('auth_success', {
				'initial_state': self.get_initial_app_state(kiosk=kiosk)
			})
			join_room('location-' + str(kiosk.location.id))
		else:
			emit('auth_error', {
				'location_id': data['location_id'],
				'hardware_id': data['hardware_id'],
				'message': 'Cannot reauthenticate this kiosk. Please manually reauthenticate.'
			})

		self.db.commit()
