ALTER TABLE hawkcards ADD facility INT NULL;
ALTER TABLE scanLog ADD facility_id INT NULL;

ALTER TABLE hawkcards ADD location_id INT NOT NULL DEFAULT 1;
ALTER TABLE hawkcards
ADD CONSTRAINT hawkcards_locations_id_fk
FOREIGN KEY (location_id) REFERENCES locations (id);