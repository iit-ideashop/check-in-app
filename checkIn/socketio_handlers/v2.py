from typing import Union, Callable, Optional, List

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

	def on_auth(self, data):
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
		self.db.commit()

		in_lab = self.get_users_list(location.id)

		emit('auth_success', {
			'initial_state': {
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
		})
