import enum
import hashlib
import hmac
import os
from datetime import date, timedelta, datetime
from typing import Union, Callable, Tuple, Optional

import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
import json

_base = declarative_base()

DBStudentIDType = sa.Integer
DBCardType = sa.Integer
ban_type = None
default_type = None

def are_equal(a, b):
	if len(a) != len(b):
		return False
	for c in a:
		if c not in b:
			return False
	return True

class Location(_base):
	__tablename__ = 'locations'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=50), nullable=False)
	secret = sa.Column(sa.LargeBinary(length=16), nullable=False)
	salt = sa.Column(sa.LargeBinary(length=16), nullable=False)
	announcer = sa.Column(sa.String(length=50), nullable=True)
	capacity = sa.Column(sa.Integer, nullable=True)
	staff_ratio = sa.Column(sa.Float, nullable=True)

	def set_secret(self, secret):
		self.salt = os.urandom(16)
		# 100,000 rounds of sha256 w/ a random salt
		self.secret = hashlib.pbkdf2_hmac('sha256', bytearray(secret, 'utf-8'), self.salt, 100000)

	def verify_secret(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.salt, 100000)
		return hmac.compare_digest(self.secret, digest)

	def __repr__(self):
		return "<Location %s>" % self.name


class Training(_base):
	__tablename__ = 'safetyTraining'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	trainee_id: int = sa.Column(DBStudentIDType, sa.ForeignKey('users.sid'), nullable=True)
	trainer_id: int = sa.Column(DBStudentIDType, sa.ForeignKey('users.sid'), nullable=True)
	machine_id = sa.Column(sa.Integer, sa.ForeignKey('machines.id'), nullable=False)
	in_person_date = sa.Column(sa.DateTime, nullable=True)
	invalidation_date = sa.Column(sa.DateTime)
	invalidation_reason = sa.Column(sa.Text)
	show_invalidation_reason = sa.Column(sa.Boolean)
	quiz_score = sa.Column(sa.DECIMAL(5, 2), nullable=True)
	quiz_date = sa.Column(sa.DateTime, nullable=True)
	quiz_attempts = sa.Column(sa.Integer, nullable=True)
	quiz_notification_sent = sa.Column(sa.DateTime, nullable=True)
	trainee = relationship('User', foreign_keys=[trainee_id], back_populates='trainings')
	trainer = relationship('User', foreign_keys=[trainer_id])
	machine = relationship('Machine', foreign_keys=[machine_id], lazy='joined')
	watched_videos = relationship('TrainingVideosBridge')
	in_person_reservation = relationship('ReservationInpersontraining')

	def __repr__(self):
		return "<%s training for %s.>" % (self.trainee.name, self.machine.name)

	def quiz_required(self):
		return self.machine.quiz is not None

	def quiz_passed(self):
		if self.quiz_score and self.machine and self.machine.quiz and self.machine.quiz.pass_score:
			return self.quiz_score >= self.machine.quiz.pass_score
		else:
			return False

	def videos_watched(self):
		db=db_session()
		if not (self.watched_videos and self.machine.videos):
			return False
		if all(y in [x.video_id for x in self.watched_videos] for y in [x.video_id for x in self.machine.videos]):
			return True
		return False

	def quiz_available_date(self):
		if self.in_person_date is not None and self.machine and self.machine.quiz_issue_days:
			return self.in_person_date + timedelta(days=self.machine.quiz_issue_days)
		elif self.machine.in_person_component is False:
			videos_watched = [x.video_id for x in self.watched_videos]
			machine_videos = [x.video_id for x in self.machine.videos]
			if not all(x in videos_watched for x in machine_videos):
				return None
			baseDate = [x.timestamp for x in self.watched_videos]
			if baseDate:
				return max(baseDate) + timedelta(days=self.machine.quiz_issue_days)
			else:
				return None
		else:
			return None

	def quiz_available(self):
		if self.in_person_date and self.machine and self.machine and self.machine.quiz_issue_days:
			return (not self.quiz_passed()) and self.in_person_date + timedelta(
				days=self.machine.quiz_issue_days) < datetime.now()
		elif self.machine.in_person_component is False:
			videos_watched = [x.video_id for x in self.watched_videos]
			machine_videos = [x.video_id for x in self.machine.videos]
			baseDate = [x.timestamp for x in self.watched_videos]
			if baseDate and all(x in videos_watched for x in machine_videos):
				return (not self.quiz_passed()) and max(baseDate) + timedelta(
					days=self.machine.quiz_issue_days) < datetime.now()
		else:
			return False

	def quiz_training_invalidated(self):
		if self.in_person_date and self.machine.quiz_grace_period_days:
			return not self.quiz_passed() and (self.in_person_date + timedelta(days=self.machine.quiz_grace_period_days) < datetime.now())
		return False

	def completed(self):
		db = db_session()
		if (self.in_person_date is None and self.machine.in_person_component is True) or (self.invalidation_date is not None):
			return False
		# checks for membership of required video in the list of all videos watched by user
		# without regard for element positions
		videos_watched = [x.video_id for x in self.watched_videos]
		machine_videos = [x.video_id for x in self.machine.videos]
		if not videos_watched or not machine_videos:
			return False
		elif all(x in videos_watched for x in machine_videos) and self.quiz_passed():
			return True
		else:
			return False

	def difference(self):
		li1 = json.loads(self.machine.videos)
		li2 = json.loads(self.videos_watched)
		return list(set(li1) - set(li2)) + list(set(li2) - set(li1))

	@classmethod
	def build_missing_trainings_string(cls, missing_trainings_list):
		data = []
		for x in missing_trainings_list:
			if x.Training is None:
				data.append((x.Machine.name, ''))
			elif x.Training.invalidation_date and x.Training.invalidation_date < datetime.utcnow():
				if x.Training.show_invalidation_reason:
					data.append((x.Machine.name, x.Training.invalidation_reason))
				else:
					data.append((x.Machine.name, ''))
			elif x.Training.quiz_training_invalidated():
				data.append((x.Machine.name, 'Incomplete quiz'))

		missing_trainings = ', '.join([x[0] + (' - ' + x[1] if x[1] else '') for x in data])
		return missing_trainings

class TrainingVideosBridge(_base):
	__tablename__ = 'trainingVideosBridge'
	training_id = sa.Column(sa.Integer, sa.ForeignKey('safetyTraining.id'), primary_key=True)
	video_id = sa.Column(sa.Integer, sa.ForeignKey('video.id'), primary_key=True)
	timestamp = sa.Column(sa.DateTime, default=sa.func.now())

	training = relationship('Training')
	video = relationship('Video')

	def __repr__(self):
		return "<%s has watched video %s for training %s>" % (self.training.trainee.name, self.video.name, self.training.machine.name)

	def getWatchedVideos(user):
		db = db_session()
		#videos_query = db.query(TrainingVideosBridge).filter_by(user_id=user).one_or_none()
		training_ids = db.query(Training.id).filter_by(trainee_id=user)
		videos_query = db.query(TrainingVideosBridge.video_id).filter(TrainingVideosBridge.training_id in training_ids.all()).all()
		if videos_query is not None:
			return videos_query
		else:
			return list()

class Major(_base):
	__tablename__ = 'majors'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=100), nullable=False)

	def __repr__(self):
		return self.name


class College(_base):
	__tablename__ = 'colleges'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=100), nullable=False)

	def __repr__(self):
		return self.name


class Status(enum.Enum):
	undergraduate = 0
	graduate = 1
	employee = 2
	inactive = 3


class User(_base):
	__tablename__ = 'users'
	sid = sa.Column(DBStudentIDType, primary_key=True, autoincrement=False)
	name = sa.Column(sa.String(length=100), nullable=False)
	photo = sa.Column(sa.String(length=100))
	pin = sa.Column(sa.LargeBinary(length=16))
	pin_salt = sa.Column(sa.LargeBinary(length=16))
	email = sa.Column(sa.String(length=100))
	major_id = sa.Column(sa.Integer, sa.ForeignKey('majors.id'))
	college_id = sa.Column(sa.Integer, sa.ForeignKey('colleges.id'))
	status = sa.Column(sa.Enum(Status))

	major = relationship('Major')
	college = relationship('College')

	def set_pin(self, pin):
		self.pin_salt = os.urandom(16)
		# 100,000 rounds of sha256 w/ a random salt
		self.pin = hashlib.pbkdf2_hmac('sha256', bytearray(pin, 'utf-8'), self.pin_salt, 100000)

	def verify_pin(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.pin_salt, 100000)
		return hmac.compare_digest(self.pin, digest)

	def location_specific(self, db: sa.orm.Session, location_id: int) -> Optional["UserLocation"]:
		return db.query(UserLocation).filter(UserLocation.sid == self.sid).filter(UserLocation.location_id == location_id).one_or_none()

	userLocation = relationship('UserLocation', lazy="dynamic")
	trainings = relationship('Training', foreign_keys=[Training.trainee_id])
	cards = relationship('HawkCard')
	warnings = relationship("Warning", foreign_keys="Warning.warnee_id", back_populates="warnee")

	def __repr__(self):
		return "<User A%d (%s)>" % (self.sid, self.name)


class UserLocation(_base):
	__tablename__ = "userLocation"
	sid = sa.Column(DBStudentIDType, sa.ForeignKey('users.sid'), primary_key=True)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), primary_key=True)
	type_id = sa.Column(sa.Integer, sa.ForeignKey('types.id'))
	waiverSigned: Optional[datetime] = sa.Column(sa.DateTime)

	def verify_pin(self, attempt):
		return self.user.verify_pin(attempt)

	@property
	def name(self):
		return self.user.name

	@property
	def photo(self):
		return self.user.photo

	@property
	def pin(self):
		return self.user.pin

	@property
	def pin_salt(self):
		return self.user.pin_salt

	user = relationship('User', lazy="joined")
	location = relationship('Location')
	access = relationship('Access', order_by='Access.timeIn')
	type = relationship('Type', lazy="joined")
	warningsGiven = relationship("Warning", foreign_keys="Warning.warner_id", back_populates="warner")

	def get_missing_trainings(self, db: sa.orm.Session):
		assert db

		trainings = db.query(Machine, Training)\
			.outerjoin(Training, sa.and_(Training.trainee_id == self.sid, Training.invalidation_date == None, Machine.id == Training.machine_id))\
			.filter(sa.and_(Machine.machineEnabled == 1, Machine.required == 1, Machine.location_id == self.location_id))\
			.all()
		missing_trainings_list = [
			x for x in trainings
			if not x.Training
				or (not x.Training.completed() and x.Training.quiz_training_invalidated())
				]
		return missing_trainings_list


class Kiosk(_base):
	__tablename__ = 'kiosks'
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)
	hardware_id = sa.Column(sa.Integer, primary_key=True, nullable=False)
	token = sa.Column(sa.String(length=65), nullable=False)
	last_seen = sa.Column(sa.DateTime, default=sa.func.now(), nullable=False)
	last_ip = sa.Column(sa.String(length=16), nullable=True)

	location = relationship('Location')

class Type(_base):
	__tablename__ = 'types'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	level = sa.Column(sa.Integer, nullable=False)
	name = sa.Column(sa.String(length=50), nullable=False)

	def __repr__(self):
		return "<Type %s>" % self.name


class Access(_base):
	__tablename__ = 'access'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	sid: Optional[int] = sa.Column(DBStudentIDType)
	timeIn = sa.Column(sa.DateTime, nullable=False)
	timeOut: Optional[datetime] = sa.Column(sa.DateTime, nullable=True, default=None)
	location_id = sa.Column(sa.Integer, nullable=False)
	hideStaff = sa.Column(sa.Boolean, nullable=False, default=False)

	user = relationship('UserLocation')
	location = relationship('Location', primaryjoin="foreign(Access.location_id)==remote(Location.id)", viewonly=True)

	__table_args__ = (
		sa.ForeignKeyConstraint((sid, location_id), (UserLocation.sid, UserLocation.location_id)),
	)

	def __repr__(self):
		return "<Access %s(%s-%s)>" % (self.user.name, str(self.timeIn), str(self.timeOut))

	@classmethod
	def getUserCount(cls, db: sa.orm.Session, location):
		users = len(db.query(Access).filter_by(location_id=location, timeOut=None).join(UserLocation, Access.sid == UserLocation.sid).join(Type,UserLocation.type_id==Type.id).filter(Type.level==0).all())
		return users
	@classmethod
	def getStaffCount(cls, db: sa.orm.Session, location):
		staff = len(db.query(Access).filter_by(location_id=location, timeOut=None).join(UserLocation, Access.sid == UserLocation.sid).join(Type,UserLocation.type_id==Type.id).filter(Type.level>0).all())
		return staff

class HawkCard(_base):
	__tablename__ = 'hawkcards'
	facility: int = sa.Column(DBCardType, primary_key=True, autoincrement=False)
	card: int = sa.Column(DBCardType, primary_key=True, autoincrement=False)
	sid: Optional[int] = sa.Column(DBStudentIDType, sa.ForeignKey(User.sid))

	user = relationship('User', lazy='joined')

	def __repr__(self):
		return "<HawkCard %d (A%d)>" % (self.card, self.sid)


class Machine(_base):
	__tablename__ = 'machines'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=50), nullable=False)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)
	required = sa.Column(sa.Boolean, nullable=False)
	quiz_id = sa.Column(sa.Integer, sa.ForeignKey('quiz.id'), nullable=True)
	quiz_issue_days = sa.Column(sa.Integer, nullable=True)
	quiz_grace_period_days = sa.Column(sa.Integer, nullable=True)

	parent_id = sa.Column(sa.VARCHAR(200), nullable = True)
	video_id = sa.Column(sa.VARCHAR(200), nullable = False)
	in_person_component = sa.Column(sa.Boolean, nullable = False)
	about_link = sa.Column(sa.VARCHAR(100), nullable = True)
	machineEnabled = sa.Column(sa.Boolean, nullable=False, default=False)
	location = relationship('Location')
	trained_users = relationship('Training')
	quiz = relationship('Quiz', lazy='joined')
	videos = relationship('VideoMachineBridge')
	reservation_type = relationship('ReservationTypes')

	def __repr__(self):
		return "<Machine %s>" % self.name

	@classmethod
	def getMachinesEnabled(cls, db: sa.orm.Session):
		machine_data = db.query(Machine.id, Machine.machineEnabled)
		machinesEnabled = {}
		for each in machine_data:
			machinesEnabled[each.id] = each.machineEnabled
		return machinesEnabled

	@classmethod
	def getMachineVideoIds(cls, db: sa.orm.Session):
		machine_data = db.query(Machine.id,Machine.video_id)
		machine_video_ids = {}
		for each in machine_data:
			machine_video_ids[each.id] = json.loads(str(each.video_id))
		return machine_video_ids


class AdminLog(_base):
	__tablename__ = 'adminLog'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	admin_id = sa.Column(DBStudentIDType)
	action = sa.Column(sa.String(length=50))
	target_id = sa.Column(DBStudentIDType, sa.ForeignKey(User.sid))
	data = sa.Column(sa.Text)
	location_id = sa.Column(sa.Integer)

	admin = relationship('UserLocation', foreign_keys=[admin_id, location_id])
	target = relationship('User', foreign_keys=[target_id])
	location = relationship('Location', primaryjoin="foreign(AdminLog.location_id) == remote(Location.id)",
	                        viewonly=True)

	__table_args__ = (
		sa.ForeignKeyConstraint((admin_id, location_id), (UserLocation.sid, UserLocation.location_id)),
	)

	def __repr__(self):
		return "<AdminLog %s (%s) %s, data=%s>" % (self.admin.name, self.action, self.target.name, self.data)


class CardScan(_base):
	__tablename__ = 'scanLog'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	card_id = sa.Column(DBCardType, nullable=False)
	facility_id = sa.Column(DBCardType, nullable=False)
	time = sa.Column(sa.DateTime, nullable=False)
	location_id = sa.Column(sa.Integer, sa.ForeignKey(Location.id), nullable=False)

	__tabkle_args__ =  (sa.ForeignKeyConstraint([facility_id, card_id], [HawkCard.facility, HawkCard.card]), {})

	card = relationship('HawkCard')
	location = relationship('Location', foreign_keys=[location_id], viewonly=True)

	def __repr__(self):
		return "<CardScan %d at %s>" % (self.card.card, self.time)


class Warning(_base):
	__tablename__ = 'warnings'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	warner_id: int = sa.Column(DBStudentIDType, nullable=False)
	warnee_id: int = sa.Column(DBStudentIDType, sa.ForeignKey("users.sid"), nullable=False)
	time = sa.Column(sa.DateTime, nullable=False, default=sa.func.now())
	reason = sa.Column(sa.Text, nullable=False)
	location_id = sa.Column(sa.Integer, nullable=False)
	comments = sa.Column(sa.Text, nullable=True)
	banned = sa.Column(sa.Boolean, nullable=False)

	warner = relationship("UserLocation", foreign_keys=(warner_id, location_id), back_populates="warningsGiven",
	                      viewonly=True)
	warnee = relationship("User", foreign_keys=(warnee_id, location_id), back_populates="warnings", viewonly=True)
	location = relationship("Location", primaryjoin="foreign(Warning.location_id) == remote(Location.id)",
	                        viewonly=True)

	__table_args__ = (
		sa.ForeignKeyConstraint((warner_id, location_id), (UserLocation.sid, UserLocation.location_id)),
	)

	@staticmethod
	def warn(db: sa.orm.Session, warner: int, warnee: int, reason: str, location: int, comments: Optional[str] = None,
	         banned: bool = False) -> "Warning":
		warnings = db.query(Warning).filter_by(warnee_id=warnee).all()
		for training in db.query(Training) \
				.filter_by(trainee_id=warnee) \
				.join(Training.machine) \
				.filter(Machine.location_id == location, Machine.required == True) \
				.all():
			numWarnings = sum(1 for _ in filter(lambda x: x.time > training.in_person_date, warnings))
			if numWarnings >= 5:
				training.invalidation_date = sa.func.now()
				training.invalidation_reason = 'System - Excessive warnings'

		warning = Warning(warner_id=warner, warnee_id=warnee, reason=reason, location_id=location, comments=comments,
		                  banned=banned)
		db.add(warning)
		return warning


class Quiz(_base):
	__tablename__ = 'quiz'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.Text, nullable=False)
	pass_score = sa.Column(sa.DECIMAL(5, 2), nullable=False, default=70.0)

	questions = relationship('Question', lazy='joined', cascade='all, delete-orphan')
	machine = relationship('Machine')

	def __repr__(self):
		return self.name


class Question(_base):
	__tablename__ = 'questions'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	quiz_id = sa.Column(sa.Integer, sa.ForeignKey('quiz.id'), nullable=False)
	prompt = sa.Column(sa.Text)
	description = sa.Column(sa.Text)
	image = sa.Column(sa.Text)
	option_type = sa.Column(sa.Text, default="radio", nullable=False)  # current allowable [radio, checkbox]

	quiz = relationship('Quiz', lazy="joined")
	option = relationship('Option', cascade='all, delete-orphan', lazy="joined")

	def __repr__(self):
		return self.prompt


class Option(_base):
	__tablename__ = 'options'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	question_id = sa.Column(sa.Integer, sa.ForeignKey('questions.id'), nullable=False)
	text = sa.Column(sa.Text)
	image = sa.Column(sa.Text)
	correct = sa.Column(sa.Boolean, default=False, nullable=False)

	question = relationship('Question', lazy="joined")

	def __repr__(self):
		return self.text

class MissedQuestion(_base):
	__tablename__ = 'missedQuestion'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	question_id = sa.Column(sa.Integer, sa.ForeignKey('questions.id'), nullable=False)
	training_id = sa.Column(sa.Integer, sa.ForeignKey('safetyTraining.id'), nullable=False)
	date = sa.Column(sa.DateTime, nullable=False, default=sa.func.now())

	training = relationship('Training', lazy="joined")
	question = relationship('Question', lazy="joined")

	def __repr__(self):
		return ("<Question %s missed on %s>" % (self.question_id, self.date))


# Like a type, but with no connection to the database so it doesn't explode if you try to use it with a different session than the one that queried for it
class TypeInfo:
	def __init__(self, type: Type):
		self.id = type.id
		self.level = type.level
		self.name = type.name

class Video(_base):
	__tablename__ = 'video'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
	length = sa.Column(sa.Integer, nullable=False)
	filepath = sa.Column(sa.Text, nullable = False)
	name = sa.Column(sa.VARCHAR(100), nullable=True)
	descrip = sa.Column(sa.Text, nullable=True)

	def getVideoNameByID(id):
		db = db_session()
		video = db.query(Video).filter_by(id=id).one_or_none()
		if video is None:
			return "video ID does not exist"
		return video.name


class VideoMachineBridge(_base):
	__tablename__ = 'videoMachineBridge'
	video_id = sa.Column(sa.Integer, sa.ForeignKey('video.id'), primary_key=True)
	machine_id = sa.Column(sa.Integer, sa.ForeignKey('machines.id'), primary_key=True)

	machine = relationship('Machine')
	video = relationship('Video')

	def __repr__(self):
		return "Machine %s requires video %s" % (self.machine.name, self.video.name)


class machineStatus(enum.Enum):
	idle		= 0
	in_use		= 1
	queued		= 2
	offline		= 3


class Energizer(_base):
	__tablename__ = 'energizer'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
	name = sa.Column(sa.Text(50),nullable=False)
	machine_id = sa.Column(sa.Integer, nullable=False)
	status = sa.Column(sa.Enum(machineStatus),nullable=True)
	timestamp = sa.Column(sa.DateTime, nullable=False)
	machine_enabled = sa.Column(sa.Integer)
	active_user = sa.Column(DBCardType,nullable=True)


class ReservationWindows(_base):
	__tablename__ = 'reservation_windows'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
	type_id = sa.Column(sa.Integer, sa.ForeignKey('reservation_types.id'), nullable=False)
	start = sa.Column(sa.DateTime,nullable=False)
	end = sa.Column(sa.DateTime, nullable=False)

	window_type = relationship('ReservationTypes')
	reservations = relationship('ReservationInpersontraining')

	def __repr__(self):
		return "<Reservation for %s, %s -> %s>" % (self.window_type.name, self.start, self.end)

class ReservationTypes(_base):
    __tablename__ = 'reservation_types'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
    name = sa.Column(sa.VARCHAR(100), nullable=False)
    duration = sa.Column(sa.Float, nullable=False)
    capacity = sa.Column(sa.Integer, nullable=False)
    machine_id = sa.Column(sa.Integer, sa.ForeignKey('machines.id'), nullable=False)

    machine = relationship('Machine')

class ReservationInpersontraining(_base):
	__tablename__ = 'reservation_inperson_training'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
	reservation_window_id = sa.Column(sa.Integer, sa.ForeignKey('reservation_windows.id'), nullable=False)
	training_id = sa.Column(sa.Integer, sa.ForeignKey('safetyTraining.id'), nullable=False)

	training = relationship('Training')
	window = relationship('ReservationWindows')

	def __repr__(self):
		return "<Reservation ID %s>" % self.id

def get_types(db) -> Tuple[TypeInfo, TypeInfo]:
	global ban_type, default_type
	ban_type = db.query(Type).filter(Type.level < 0).first()
	if not ban_type:
		ban_type = Type(level=-10, name="Banned")
		db.add(ban_type)
		db.commit()
	default_type = db.query(Type).filter(Type.level == 0).first()
	if not default_type:
		default_type = Type(level=0, name="Users")
		db.add(default_type)
		db.commit()

	ban_type = TypeInfo(ban_type)
	default_type = TypeInfo(default_type)
	return default_type, ban_type


# Just for type-hinting, if you know a better way please fix
class HasRemoveMethod:
	def remove(self):
		pass


db_session = None



def init_db(connection_string: str) -> Union[Callable[[], sa.orm.Session], HasRemoveMethod]:
	global default_type, ban_type, engine, db_session
	engine = sa.create_engine(connection_string, pool_size=50, max_overflow=150, pool_recycle=3600, encoding='utf-8')
	db_session = scoped_session(sessionmaker(bind=engine))
	_base.metadata.create_all(engine)
	db = db_session()
	default_type, ban_type = get_types(db)
	db.close()
	return db_session
