from flask_socketio import Namespace

class SocketV2Namespace(Namespace):
	def __init__(self, namespace, db_session, app):
		self.db_session = db_session
		self.app = app
		super().__init__(namespace)

	def on_connect(self):
		pass

	def on_disconnect(self):
		pass