ALTER TABLE users ADD email VARCHAR(100) COLLATE utf8_bin DEFAULT NULL;
ALTER TABLE users ADD major_id int(11) DEFAULT NULL;
ALTER TABLE users ADD type enum('Graduate', 'Undergraduate', 'Alumnus') COLLATE utf8_bin DEFAULT NULL;

CREATE TABLE IF NOT EXISTS `majors` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`major` varchar(50) COLLATE utf8_bin NOT NULL,
	`college` varchar(50) COLLATE utf8_bin NOT NULL,
	PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE users ADD CONSTRAINT users_major FOREIGN KEY (major_id) REFERENCES majors (id);