-- USAGE:
--  Drop all tables from checkIn_dev
--  Run checkIn.py targeting checkIn_dev once to create the schema
--  Run this on checkIn_dev to copy data from checkIn
--  Dump checkIn_dev to an sql file
--  Modify the dump file to target checkIn
--  Import the dump file to update checkIn

INSERT INTO locations (id, name, secret, salt, announcer, capacity, staff_ratio) SELECT id, name, secret, salt, announcer, capacity, staff_ratio FROM checkIn.locations;

INSERT INTO types (level, name) VALUES (75, 'Lab Mentor'), (85, 'Lab Technician'), (90, 'Developer'), (100, 'Lab Manager');

INSERT INTO users (sid, name, photo, pin, pin_salt) SELECT sid, name, photo, pin, pin_salt FROM checkIn.users where location_id = 1;
UPDATE users SET photo = NULL where photo = "";
INSERT INTO users (sid, name, photo, pin, pin_salt) SELECT sid, name, photo, pin, pin_salt FROM checkIn.users where location_id = 2 ON DUPLICATE KEY UPDATE name = VALUES(name), photo = COALESCE(VALUES(photo), checkIn_dev.users.photo), pin = COALESCE(VALUES(pin), checkIn_dev.users.pin), pin_salt = COALESCE(VALUES(pin_salt), checkIn_dev.users.pin_salt);
UPDATE users SET photo = NULL where photo = "";
INSERT INTO users (sid, name, photo, pin, pin_salt) SELECT sid, name, photo, pin, pin_salt FROM checkIn.users where location_id = 3 ON DUPLICATE KEY UPDATE name = VALUES(name), photo = COALESCE(VALUES(photo), checkIn_dev.users.photo), pin = COALESCE(VALUES(pin), checkIn_dev.users.pin), pin_salt = COALESCE(VALUES(pin_salt), checkIn_dev.users.pin_salt);
UPDATE users SET photo = NULL where photo = "";

INSERT INTO userLocation (sid, location_id, type_id, waiverSigned) SELECT sid, checkIn.users.location_id, checkIn_dev.types.id, waiverSigned FROM checkIn.users JOIN checkIn.types on checkIn.users.type_id = checkIn.types.id JOIN types on checkIn.types.level = checkIn_dev.types.level;

INSERT INTO access (id, sid, timeIn, timeOut, location_id) SELECT id, sid, timeIn, timeOut, location_id FROM checkIn.access;

INSERT INTO adminLog (id, admin_id, action, target_id, data, location_id) SELECT id, admin_id, action, target_id, data, location_id FROM checkIn.adminLog;

INSERT INTO hawkcards (sid, card) SELECT sid, card FROM checkIn.hawkcards WHERE location_id = 1;
INSERT INTO hawkcards (sid, card) SELECT sid, card FROM checkIn.hawkcards WHERE location_id = 2 ON DUPLICATE KEY UPDATE sid = COALESCE(VALUES(sid), checkIn_dev.hawkcards.sid);
INSERT INTO hawkcards (sid, card) SELECT sid, card FROM checkIn.hawkcards WHERE location_id = 3 ON DUPLICATE KEY UPDATE sid = COALESCE(VALUES(sid), checkIn_dev.hawkcards.sid);

INSERT INTO kiosks (location_id, hardware_id, token, last_seen, last_ip) SELECT location_id, hardware_id, token, last_seen, last_ip FROM checkIn.kiosks;

INSERT INTO machines (id, name, location_id) SELECT id, name, location_id FROM checkIn.machines;

INSERT INTO safetyTraining (id, trainee_id, trainer_id, machine_id, date) SELECT id, trainee_id, trainer_id, machine_id, date FROM checkIn.safetyTraining;

INSERT INTO scanLog (id, card_id, time, location_id) SELECT id, card_id, time, location_id FROM checkIn.scanLog;

INSERT INTO warnings (id, warner_id, warnee_id, time, reason, location_id, comments, banned) SELECT id, warner_id, warnee_id, time, reason, location_id, comments, banned FROM checkIn.warnings;