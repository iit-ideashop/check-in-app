import cv2 as cv
import sys
import math
import time
import os
from pydub import AudioSegment
from pydub.playback import play

# Pass camera as first program argument
camera = int(sys.argv[1])
print("Using camera " + str(camera))
video = cv.VideoCapture(camera)
## Configuration
# Box comparison options
maxDistanceDifference = 100 # Maximum movement between centers of two boxes for them to be considered as the same box moving (anything that moves more than this in one frame will be considered as two separate boxes) 
maxPctAreaDifference = 0.5 # Maximum change in area between two boxes for them to be considered as the same box.  This is a percentage, if the smaller box is less than this fraction in area of the bigger box, it will be considered.

# Person detection options
minSize = 20000 # The minimum size of a box for it to be considered a person
if len(sys.argv) > 2: # Can be passed as the second argument as well
	minSize = float(sys.argv[2])

# Person must be moving in the same direction for this amount of time before a notice is played
requiredTimeToActivate = 0.2
# The same notice won't be played more than once ever this number of seconds
minTimeBetweenPlays = 6
# Function that is run if a person is detected walking in the positive direction (from left to right in camera view)
def playSoundMovingPositive():
	print("Playing sound!")
	segment = AudioSegment.from_ogg("clean_up.ogg")
	play(segment)
# Function that is run if a person is detected walking in the negative direction (from right to left in camera view)
def playSoundMovingNegative():
	segment = AudioSegment.from_ogg("announcement.ogg")
	play(segment)


_, last = video.read()
last = cv.cvtColor(last, cv.COLOR_BGR2GRAY)
lastContours = []
lastPlay = 0
class ChangeTracker:
	def __init__(self, timeToActivate, minTimeBetweenPlays):
		self.timeToActivate = timeToActivate
		self.minTimeBetweenPlays = minTimeBetweenPlays
		self.OKStart = time.time()
		self.lastPlay = 0

	def update(self, ok):
		if not ok:
			self.OKStart = time.time()

	def shouldActivate(self):
		if (time.time() - self.lastPlay) < self.minTimeBetweenPlays:
			return False
		if (time.time() - self.OKStart) > self.timeToActivate:
			self.lastPlay = time.time()
			return True
		else:
			return False
negTracker = ChangeTracker(requiredTimeToActivate, minTimeBetweenPlays)
posTracker = ChangeTracker(requiredTimeToActivate, minTimeBetweenPlays)

# Compare two images and return a array of interesting looking boxes (spots with large amounts of movement)
def compareImages(img1, img2):
	diff = cv.absdiff(img1, img2)
	thresh = cv.threshold(diff, 40, 255, cv.THRESH_BINARY)[1]
	thresh = cv.dilate(thresh, None, iterations=2)
	cv.imshow("Threshold", thresh)
	contours = [contour for contour in cv.findContours(thresh.copy(), cv.RETR_EXTERNAL,
		cv.CHAIN_APPROX_SIMPLE)[1] if cv.contourArea(contour) > minSize]
	return contours

# Decides whether boxes from two consecutive frames are similar enough to be considered one box moving
# If yes, returns a pair of the coordinates of their centers
# If no, returns None
def areSimilar(box1, box2):
	area1 = cv.contourArea(box1)
	area2 = cv.contourArea(box2)
	if area1 > area2:
		areaDiff = area2 / area1
	else:
		areaDiff = area1 / area2
	if areaDiff < maxPctAreaDifference:
		print(f"Area cutoff, {areaDiff} < {maxPctAreaDifference}")
		return None
	(x1, y1, w1, h1) = cv.boundingRect(box1)
	(x2, y2, w2, h2) = cv.boundingRect(box2)
	center1x = (x1 + w1 // 2)
	center1y = (y1 + h1 // 2)
	center2x = (x2 + w2 // 2)
	center2y = (y2 + h2 // 2)
	movementx = center2x - center1x
	movementy = center2y - center1y
	distance = math.sqrt(movementx ** 2 + movementy ** 2)
	if distance > maxDistanceDifference:
		print(f"Distance cutoff, {distance} > {maxDistanceDifference}")
		return None
	print("Matched")
	return ((center1x, center1y), (center2x, center2y))

# Decide whether or not a sound should be played
def checkAndPlaySound():
	if posTracker.shouldActivate():
		playSoundMovingPositive()
		posTracker.update(False)
		negTracker.update(False)
	elif negTracker.shouldActivate():
		playSoundMovingNegative()
		posTracker.update(False)
		negTracker.update(False)
	

while True:
	grabbed, img = video.read()
	if not grabbed:
		break

	gray = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
	contours = compareImages(last, gray)	

	for contour in contours:
		(x, y, w, h) = cv.boundingRect(contour)
		# Draw boxes
		cv.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)

	foundPos = False
	foundNeg = False
	for lastBox in lastContours:
		for curBox in contours:
			points = areSimilar(lastBox, curBox)
			if points == None:
				continue
			if (points[0][0] < points[1][0]):
				cv.arrowedLine(img, points[0], points[1], (0, 255, 255), thickness=2)
				foundPos = True
			else:
				cv.arrowedLine(img, points[0], points[1], (0, 0, 255), thickness=2)
				foundNeg = True
	negTracker.update(foundNeg)
	posTracker.update(foundPos)
	checkAndPlaySound()

	cv.imshow("Final", img)
	last = gray
	lastContours = contours
	key = cv.waitKey(1) & 0xFF
	if key == ord("q"):
		break
