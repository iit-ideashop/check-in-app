import base64
import os
import sqlalchemy as sa
from flask import Blueprint, render_template, request, session, redirect, url_for, g
from checkIn.model import Kiosk, Location

auth_controller = Blueprint('auth', __name__)

@auth_controller.route('/auth', methods=['GET', 'POST'])
def auth():
	locations = g.db.query(Location).all()
	if request.method == 'GET':
		return render_template('auth.html', locations=locations)
	else:
		if 'hwid' not in request.form or 'location' not in request.form or 'secret' not in request.form:
			return render_template('auth.html', error='Please complete all fields.', locations=locations)

		location = g.db.query(Location).filter_by(id=int(request.form['location'])).one_or_none()
		if not location:
			return render_template('auth.html', error='Internal server error: the location went away',
			                       locations=locations)
		if not location.verify_secret(request.form['secret']):
			return render_template('auth.html', error='Invalid secret!', locations=locations)

		new_token = base64.urlsafe_b64encode(os.urandom(33)).decode('ascii')
		kiosk = g.db.query(Kiosk) \
			.filter_by(hardware_id=request.form['hwid']) \
			.one_or_none()

		if kiosk:
			# deauthorize any existing kiosks with that ID
			g.socketio.emit('go', {'to': url_for('.auth'), 'hwid': kiosk.hardware_id})

			kiosk.token = new_token
			kiosk.location_id = request.form['location']
			kiosk.last_seen = sa.func.now()

		else:
			kiosk = Kiosk(location_id=request.form['location'],
			              hardware_id=request.form['hwid'],
			              token=new_token,
			              last_seen=sa.func.now())
			g.db.add(kiosk)

		g.db.commit()

		session['location_id'] = kiosk.location_id
		session['hardware_id'] = int(request.form['hwid'])
		session['token'] = new_token

		return redirect('/')


@auth_controller.route('/deauth', methods=["POST"])
def deauth():
	g.db.query(Kiosk).filter_by(location_id=session['location_id'], hardware_id=session['hardware_id']).delete()
	g.db.commit()
	return redirect('/auth')


@auth_controller.route('/deauth/<int:loc>/<int:hwid>', methods=["POST"])
def deauth_other(loc, hwid):
	if not g.admin or g.admin.location_id != session['location_id']or g.admin.type.level < 90:
		return redirect('/')

	g.socketio.emit('go', {'to': url_for('.deauth'), 'hwid': hwid})

	g.db.query(Kiosk).filter_by(location_id=loc, hardware_id=hwid).delete()
	g.db.commit()
	return redirect('/admin/locations/' + str(loc))
