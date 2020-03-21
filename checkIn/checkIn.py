# all the imports
import os, sys

sys.path.insert(0, os.path.abspath(".."))

import argparse
import logging.config
from flask import Flask, request, session, g, redirect, url_for, render_template
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO
import sqlalchemy as sa
from sqlalchemy.orm import joinedload
from checkIn.model import UserLocation, Access, Kiosk, Location, init_db, get_types
from checkIn.controllers.auth import auth_controller
from checkIn.controllers.userflow import userflow_controller
from checkIn.controllers.api import api_controller
from checkIn.controllers.admin import admin_controller
from checkIn.socketio_handlers.v1 import SocketV1Namespace
from checkIn.socketio_handlers.v2 import SocketV2Namespace

version = "1.0.0"

app = Flask(__name__, static_url_path='/static', static_folder='static')  # create the application instance :)
socketio = SocketIO(app, manage_session=True, logger=True)
app.config.from_object(__name__)
app.config.from_pyfile('config.cfg')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

logging.config.dictConfig({
	'version': 1,
	'formatters': {'default': {
		'format': '[%(asctime)s] %(levelname)-7s %(message)s',
		'datefmt': '%m/%d/%Y %I:%M:%S %p'
	}},
	'handlers': {
		'wsgi': {
			'class': 'logging.StreamHandler',
			'stream': 'ext://flask.logging.wsgi_errors_stream',
			'formatter': 'default'
		},
		'file': {
			'level': 'INFO',
			'class': 'logging.handlers.RotatingFileHandler',
			'formatter': 'default',
			'filename': app.config['LOGFILE'],
			'maxBytes': 8000000,
			'backupCount': 3
		}
	},
	'root': {
		'level': 'INFO',
		'handlers': ['wsgi', 'file']
	}
})

Bootstrap(app)

db_session = init_db(app.config['DB'])
db = db_session()
default_type, ban_type = get_types(db)
db.close()
app.logger.info('Server started.')

io_controller = SocketV1Namespace('/', db_session, app)
socketio.on_namespace(io_controller)

io_controller_v2 = SocketV2Namespace('/v2', db_session, app)
socketio.on_namespace(io_controller_v2)


@app.before_request
def before_request():
	db = db_session()
	g.socketio = socketio
	g.db = db
	g.io_controller = io_controller

	if 'location_id' not in session \
			and request.endpoint != 'auth.auth' \
			and request.endpoint != 'api.card_read' \
			and request.endpoint != '/error' \
			and str(request.path[0:7]) != '/static':
		return redirect(url_for('auth.auth'))

	if request.endpoint and request.endpoint != 'api.card_read' and \
			'socket.io' not in request.path and \
			'static' not in request.path and \
			'/auth' not in request.path:
		kiosk = db.query(Kiosk).get(session['hardware_id'])
		if kiosk and kiosk.token == session['token']:
			kiosk.last_seen = sa.func.now()
			kiosk.last_ip = request.remote_addr
			db.commit()
		else:
			return redirect("/auth")

		in_lab = db.query(Access) \
			.filter_by(timeOut=None) \
			.filter_by(location_id=session['location_id']) \
			.options(joinedload(Access.user)) \
			.all() \
			if 'location_id' in session else list()

		g.location = db.query(Location).filter_by(
			id=session['location_id']).one_or_none() if 'location_id' in session else None
		g.students = [a.user for a in in_lab if a.hideStaff or a.user.type.level <= 0]
		g.staff = [a.user for a in in_lab if not a.hideStaff and a.user.type.level > 0]
		g.staff.sort(key=lambda x: x.type.level, reverse=True)
		g.admin = db.query(UserLocation).filter_by(sid=session['admin'], location_id=session['location_id']).one_or_none() if 'admin' in session else None
		g.version = version
		g.kiosk = kiosk

		for student in g.students:
			if not student.get_missing_trainings(db):
				student.general_training = True
			else:
				student.general_training = False


@app.teardown_appcontext
def close_db(error):
	db_session.remove()


@app.errorhandler(Exception)
def exception_handler(error):
	app.logger.error(error, exc_info=True)
	return render_template("internal_error.html"), 500


@app.errorhandler(404)
def error_404(error):
	return render_template("internal_error.html"), 500


@app.route('/error')
def display_error():
	return render_template("internal_error.html"), 500


app.register_blueprint(auth_controller)
app.register_blueprint(userflow_controller)
app.register_blueprint(api_controller)
app.register_blueprint(admin_controller)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Idea Shop Check In App')
	# parser.add_argument('-p', '--port', help='set the port to bind on', type=int)
	parser.add_argument('-a', '--admin', help='invoke admin tools instead of starting the web app', action='store_true')
	parser.add_argument('-l', '--location', help='choose the location to operate on', type=int)
	parser.add_argument('-s', '--secret', help='set a location\'s secret', type=str)
	args = parser.parse_args()

	if args.admin:
		_db = db_session()
		location = _db.query(Location).filter_by(id=args.location).one_or_none()
		if not location:
			print('Location %d does not exist!' % args.location)
			exit(404)

		if args.secret:
			location.set_secret(args.secret)
			_db.commit()
			print('Secret for %s (%d) updated.' % (location.name, location.id))
			exit(0)
		else:
			print('Location %d: %s' % (location.name, location.id))
			exit(0)

	app.jinja_env.auto_reload = True
	app.config['TEMPLATES_AUTO_RELOAD'] = True
	sslInfo = {}
	if "SSLCERT" in app.config and "SSLKEY" in app.config:
		sslInfo = {"certfile": app.config["SSLCERT"], "keyfile": app.config["SSLKEY"]}

	socketio.run(app, host='0.0.0.0', **sslInfo)
