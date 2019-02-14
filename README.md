# Idea Shop Check-in App
A project of the Idea Shop at the Illinois Institute of Technology, this
web app provides a sign-in system to track and manage usage of our
machine shop.

## Getting started
We haven't yet figured out an optimal deployment procedure, those instructions
will be shown here when we have a process available. The following instructions
are dependent on Flask's Werkzeug development server and should NOT be exposed
to a public network -- for development purposes only.

### Prerequisites
* `flask`
* `flask-bootstrap`
* `flask-socketio`
* `sqlalchemy`
* `pysimplesoap` (dependency of [nkaminski/IITLookUp](https://github.com/nkaminski/IITLookUp) which is integrated
    in this project)
* An application server running Python 3.6 (earlier versions are not supported)
* A database server [compatible with SQLAlchemy](http://docs.sqlalchemy.org/en/latest/core/engines.html#supported-databases)
(the application is written with MariaDB/MySQL in mind)
* [nkaminski/piProx-oss](https://github.com/nkaminski/piProx-oss) or a compatible software (see below for interface documentation)
* A touchscreen of resolution higher than 1280 x 1024

The Idea Shop's setup runs this on a Raspberry Pi using a generic HID
card reader, compatible with our school-issued RFID cards.

### Installation
1. Copy config.cfg.default to config.cfg.
2. Fill in config.cfg with database and university lookup credentials.
The `DB` field should be filled out according to [the SQLAlchemy documentation](http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)
3. `pip install` your database driver of choice. The Idea Shop's installation
uses pymysql. (For MySQL, we highly recommend **not** using the default MySQL Connector for Python, because it returns all
strings as byte arrays and neither SQLAlchemy nor our program is set up to handle that, leading to every string stored in the 
database being displayed in the app as `b'string'`.)
4. To start the app, run `python (or python3) checkIn.py`. The database
tables will be automatically generated.

## Card reader API
This application exposes a very simple (and very insecure at the moment) interface for card readers. A card read currently
is triggered by an HTTP POST request to `/card_read/<location_id>` resembling an HTML form submission with at least 2 fields:
* `facility` - the card's facility ID, currently unused
* `cardnum` - the card's individual identifier

Any additional fields are discarded for the time being.

[nkaminski/piProx-oss](https://github.com/nkaminski/piProx-oss) provides a working implementation of this interface in `http-client.c`.

## License
This project is licensed under the GNU Affero General Public License,
version 3. Please see README.md for the full text.

Interaction required sound effects are copyright (c) soundeffects+.
Banned user sound effect is from [AdamWeeden on freesound.org](https://freesound.org/people/AdamWeeden/sounds/255181/), licensed CC-BY 3.0
