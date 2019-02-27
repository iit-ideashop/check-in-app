from datetime import date, datetime, timedelta
import sqlalchemy as sa
from sqlalchemy import distinct, func
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

DB='mysql+pymysql://<user>:<password>@<ipaddr>/checkIn?charset=utf8'

engine = sa.create_engine(DB, pool_recycle=3600, encoding='utf-8')
Base = declarative_base()

class Location(Base):
	__tablename__ = 'locations'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=50), nullable=False)
	secret = sa.Column(sa.Binary(length=16), nullable=False)
	salt = sa.Column(sa.Binary(length=16), nullable=False)

	def set_secret(self, secret):
		self.salt = os.urandom(16)
		# 100,000 rounds of sha256 w/ a random salt
		self.secret = hashlib.pbkdf2_hmac('sha256', bytearray(secret, 'utf-8'), self.salt, 100000)

	def verify_secret(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.salt, 100000)
		return hmac.compare_digest(self.secret, digest)

	def __repr__(self):
		return "<Location %s>" % self.name


class Kiosk(Base):
	__tablename__ = 'kiosks'
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), primary_key=True, nullable=False)
	hardware_id = sa.Column(sa.Integer, primary_key=True, nullable=False)
	token = sa.Column(sa.String(length=65), nullable=False)
	last_seen = sa.Column(sa.DateTime, default=sa.func.now())

	location = relationship('Location')


class Type(Base):
	__tablename__ = 'types'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	level = sa.Column(sa.Integer, nullable=False)
	name = sa.Column(sa.String(length=50), nullable=False)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

	def __repr__(self):
		return "<Type %s>" % self.name


class Access(Base):
	__tablename__ = 'access'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	sid = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	timeIn = sa.Column(sa.DateTime, nullable=False)
	timeOut = sa.Column(sa.DateTime, default=None)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

	user = relationship('User')
	location = relationship('Location')

	def __repr__(self):
		return "<Access %s(%s-%s)>" % (self.user.name, str(self.timeIn), str(self.timeOut))


class HawkCard(Base):
	__tablename__ = 'hawkcards'
	sid = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	card = sa.Column(sa.BigInteger, primary_key=True)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'))

	user = relationship('User')
	location = relationship('Location')

	def __repr__(self):
		return "<HawkCard %d (A%d)>" % (self.card, self.sid)


class Machine(Base):
	__tablename__ = 'machines'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	name = sa.Column(sa.String(length=50))
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

	location = relationship('Location')

	def __repr__(self):
		return "<Machine %s>" % self.name


class Training(Base):
	__tablename__ = 'safetyTraining'
	id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
	trainee_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	trainer_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	machine_id = sa.Column(sa.Integer, sa.ForeignKey('machines.id'))
	date = sa.Column(sa.DateTime)

	trainee = relationship('User', foreign_keys=[trainee_id], back_populates='trainings')
	trainer = relationship('User', foreign_keys=[trainer_id])
	machine = relationship('Machine', foreign_keys=[machine_id])

	def __repr__(self):
		return "<%s trained %s on %s, time=%s>" % \
			   (self.trainer.name, self.trainee.name, self.machine.name, str(self.date))


class User(Base):
	__tablename__ = 'users'
	sid = sa.Column(sa.BigInteger, primary_key=True)
	name = sa.Column(sa.String(length=100), nullable=False)
	type_id = sa.Column(sa.Integer, sa.ForeignKey('types.id'))
	waiverSigned = sa.Column(sa.DateTime)
	photo = sa.Column(sa.String(length=100), default='')
	location_id = sa.Column(sa.INTEGER, sa.ForeignKey('locations.id'), nullable=False, primary_key=True)
	pin = sa.Column(sa.Binary(length=16))
	pin_salt = sa.Column(sa.Binary(length=16))

	def set_pin(self, pin):
		self.pin_salt = os.urandom(16)
		# 100,000 rounds of sha256 w/ a random salt
		self.pin = hashlib.pbkdf2_hmac('sha256', bytearray(pin, 'utf-8'), self.pin_salt, 100000)

	def verify_pin(self, attempt):
		digest = hashlib.pbkdf2_hmac('sha256', bytearray(attempt, 'utf-8'), self.pin_salt, 100000)
		return hmac.compare_digest(self.pin, digest)

	def __repr__(self):
		return "<Location %s>" % self.name

	type = relationship('Type')
	location = relationship('Location')
	trainings = relationship('Training', foreign_keys=[Training.trainee_id])
	access = relationship('Access', order_by='Access.timeIn')
	cards = relationship('HawkCard')

	def __repr__(self):
		return "<User A%d (%s)>" % (self.sid, self.name)


class AdminLog(Base):
	__tablename__ = 'adminLog'
	id = sa.Column(sa.BigInteger, primary_key=True, autoincrement=True)
	admin_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	action = sa.Column(sa.String(length=50))
	target_id = sa.Column(sa.BigInteger, sa.ForeignKey('users.sid'))
	data = sa.Column(sa.Text)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'))

	admin = relationship('User', foreign_keys=[admin_id])
	target = relationship('User', foreign_keys=[target_id])
	location = relationship('Location')

	def __repr__(self):
		return "<AdminLog %s (%s) %s, data=%s>" % (self.admin.name, self.action, self.target.name, self.data)


class CardScan(Base):
	__tablename__ = 'scanLog'
	id = sa.Column(sa.BigInteger, primary_key=True, autoincrement=True)
	card_id = sa.Column(sa.BigInteger, sa.ForeignKey('hawkcards.card'), nullable=False)
	time = sa.Column(sa.DateTime)
	location_id = sa.Column(sa.Integer, sa.ForeignKey('locations.id'), nullable=False)

	card = relationship('HawkCard')
	location = relationship('Location')

	def __repr__(self):
		return "<CardScan %d at %s>" % (self.card, self.time)


# create tables if they don't exist
db_session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(engine)

db = db_session()

def main():
    startDate = datetime(2019,1,1,0,0,0)
    endDate = datetime(2019,2,28,23,59,59)
    print(str(uniqueStudents(startDate, endDate)) + " unique students.")
    print(str(uniqueVisits(startDate, endDate)) + " visits.")
    print(str(studentWorkHours(startDate, endDate)) + " student work hours.")
    print(str(avgVisitLength(startDate, endDate)) + " minutes average visit length.")
    #print("%s is the heaviest user at %s hours" % tuple(heaviestUser(startDate, endDate)))
    print(busiestTime(startDate, endDate))
    print(avgBusiestTime(startDate, endDate))
    print("%s total trainings. %s has trained the most, %s total students in %s trainings." % tuple(trainings(startDate, endDate)))
    return

def uniqueStudents(startDate, endDate):
    return db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).group_by(Access.sid).filter(Access.user.has(User.type.has(Type.level == 0))).count()

def uniqueVisits(startDate, endDate):
    return db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).filter(Access.user.has(User.type.has(Type.level == 0))).count()

def studentWorkHours(startDate, endDate):
    sum = 0
    for each in db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).filter(Access.user.has(User.type.has(Type.level == 0))):
        sum += (each.timeOut-each.timeIn).total_seconds()
    return sum/(60*60)

def avgVisitLength(startDate, endDate):
    sum = 0
    count = 0
    for each in db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).filter(Access.user.has(User.type.has(Type.level == 0))):
        sum += (each.timeOut-each.timeIn).total_seconds()
        count += 1
    return (sum/count)/60

def heaviestUser(startDate, endDate):
    users = []
    for each in db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).filter(Access.user.has(User.type.has(Type.level == 0))).order_by(Access.sid):
      time = (each.timeOut-each.timeIn).total_seconds()
      if not users:
        users.append([each.sid,time])
      elif each.sid == users[-1][0]:
        users[-1][1] += time
      else:
        users.append([each.sid,time])
    result = sorted(users, key=lambda x: x[1], reverse=True)[0]
    return [db.query(User.name).filter_by(sid = result[0]).one().name, result[1]/(60*60)]

def busiestTime(startDate, endDate):
    accessList = db.query(Access).filter(Access.timeIn > startDate).filter(Access.timeOut < endDate).filter(Access.user.has(User.type.has(Type.level == 0))).order_by(Access.sid)
    timeList = []
    current = 0
    max = [1,0,0]
    for access in accessList:
      timeList.append(["timeIn", access.timeIn])
      timeList.append(["timeOut", access.timeOut])
    timeList.sort(key=lambda x: x[1])
    for index, action in enumerate(timeList):
      if action[0] == "timeIn":
        current += 1
      else:
        current -= 1
      if current >= max[0]:
        max = [current, action[1], timeList[index+1][1]]
    if max == [1,0,0]:
      return
    else:
      return max

def avgBusiestTime(startDate, endDate):
    days = []
    for i in range((endDate - startDate).days + 1):
      new = busiestTime(startDate+timedelta(days=i-1),startDate+timedelta(days=i))
      if new:
        days.append(new)
    sum = 0
    for i in days:
      sum += i[0]
    return sum/len(days)


def trainings(startDate, endDate):
    trainings = db.query(Training).filter(Training.trainer.has(User.type.has(Type.level == 75))).filter(Training.date > startDate).filter(Training.date < endDate).group_by(func.date_format(Training.date, '%Y-%m-%d %H:%i:00')).order_by(Training.trainer_id)
    training_count = []
    for training in trainings:
        if not training_count:
            training_count.append([training.trainer_id,db.query(User.name).filter_by(sid = training.trainer_id).first().name,1,db.query(Training).filter(Training.date > startDate).filter(Training.date < endDate).filter(Training.trainer_id == training.trainer_id).count()])
        elif training.trainer_id == training_count[-1][0]:
            training_count[-1][2] += 1
        else:
            training_count.append([training.trainer_id,db.query(User.name).filter_by(sid = training.trainer_id).first().name,1,db.query(Training).filter(Training.date > startDate).filter(Training.date < endDate).filter(Training.trainer_id == training.trainer_id).count()])
    training_count = sorted(training_count, key=lambda x: x[2], reverse=True)
    for each in training_count:
        print("%s trained %s users in %s training sessions." % (each[1],each[3],each[2]))
    return(trainings.count(),training_count[0][1],training_count[0][3],training_count[0][2])

if __name__ == "__main__":
    main()
