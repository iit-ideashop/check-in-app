from setuptools import setup

setup(
        name='checkIn',
        packages=['checkIn'],
        include_package_data=True,
        install_requires=[
            'flask',
            'flask-bootstrap',
            'flask-socketio',
            'sqlalchemy',
            'pysimplesoap'
            ],
)
