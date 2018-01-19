if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from .checkIn import socketio, app as application

if __name__ == '__main__':
    socketio.run(application)