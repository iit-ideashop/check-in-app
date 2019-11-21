from checkIn import db_session, User, Major, College, Status
import argparse
import csv
from typing import Optional, List, Set, Dict

batch_size = 1000
batch_count = 0

def parse_status(status: str) -> Optional[Status]:
	"""
	Parse the status from a CSV field
	:param status: Status.undergraduate or Status.graduate
	:return: The status
	"""
	text = status.strip().lower()
	if text == 'undergraduate':
		return Status.undergraduate
	if text == 'graduate' or text == 'graduate business' or text == 'law' or text == 'master of laws':
		return Status.graduate
	else:
		return None


def compare_terms(a: str, b: str) -> int:
	"""
	Compare 2 academic terms in the form of "[Fall|Spring|Summer] [year]".
	:return: True if b is later than a, otherwise False.
	"""

	a_split = a.split(' ')
	b_split = b.split(' ')

	a_year = int(a_split[1])
	b_year = int(b_split[1])

	if b_year == a_year:
		term_map = {'Spring': 0, 'Summer': 1, 'Fall': 2}
		a_term = term_map[a_split[0]]
		b_term = term_map[b_split[0]]
		return b_term > a_term

	else:
		return b_year > a_year


def reformat_name(name: str) -> str:
	"""
	Reformat a name "Last, First" to "First Last"
	"""
	return ' '.join(name.split(', ')[::-1])


if __name__ == '__main__':
	records_created = 0
	records_updated = 0
	records_bypassed = 0
	parser = argparse.ArgumentParser(description='Check-in App Student Import Script')
	parser.add_argument('csvfile', type=str,
	                    help='The file to load data from.')
	parser.add_argument('term', type=str,
	                    help='The current term. Valid options are fall, spring, and summer.',
	                    choices=['fall', 'spring', 'summer'])
	parser.add_argument('year', type=int,
	                    help='The current year.')
	args = parser.parse_args()

	term: str = '%s %d' % (args.term.capitalize(), args.year)

	with open(args.csvfile, 'r') as csvfile:
		reader: csv.DictReader = csv.DictReader(csvfile, quotechar='"', delimiter=',')
		db = db_session()

		# see who we have already
		colleges: List[College] = db.query(College).all()
		majors: List[Major] = db.query(Major).all()
		users: List[User] = db.query(User).all()

		# last term we've seen for each user, just in case terms are out of order
		user_terms: Dict[int, str] = {}

		existing_users: Dict[int, User] = {s.sid: s for s in users}
		existing_colleges: Dict[str, College] = {c.name: c for c in colleges}
		existing_majors: Dict[str, Major] = {m.name: m for m in majors}

		for row in reader:
			college: str = row['COLLEGE_DESC']
			major: str = row['MAJOR_DESC']
			sid: int = int(row['ID'][1:])
			status: Optional[Status] = parse_status(row['STUDENT_LEVEL_DESC'])

			user: Optional[User] = existing_users.get(sid)

			row_op = ' '
			if not user:
				user = User(sid=sid, name=reformat_name(row['NAME']), email=row['EMAIL_PREFERRED_ADDRESS'])
				db.add(user)
				row_op = '+'

			# don't update anything if we've already seen newer data
			if sid not in user_terms.keys() or compare_terms(user_terms[sid], row['ACADEMIC_PERIOD_DESC']):
				user_terms[sid] = row['ACADEMIC_PERIOD_DESC']

				user.email = row['EMAIL_PREFERRED_ADDRESS']

				user.college = existing_colleges.get(college)
				if not user.college:
					existing_colleges[college] = College(name=college)
					db.add(existing_colleges[college])
					print('[+] College - %s' % college)

				user.major = existing_majors.get(major)
				if not user.major:
					existing_majors[major] = Major(name=major)
					db.add(existing_majors[major])
					print('[+] Major - %s' % major)

				if row['ACADEMIC_PERIOD_DESC'] == term:
					user.status = status
				elif compare_terms(row['ACADEMIC_PERIOD_DESC'], term):
					user.status = None

				row_op = '~'

			print('[%s] A%d  %s  %s' % (row_op, sid, row['ACADEMIC_PERIOD_DESC'].rjust(12), user.name if user else reformat_name(row['NAME'])))
			if row_op == '+':
				records_created += 1
				batch_count += 1
			elif row_op == '~':
				records_updated += 1
				batch_count += 1
			else:
				records_bypassed += 1

			if batch_count > batch_size:
				print('[C] Committing batch')
				db.commit()

	db.commit()
	print('Summary: %d created, %d updated, %d bypassed' % (records_created, records_updated, records_bypassed))

