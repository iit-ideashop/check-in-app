drop table if exists entries;
create table scanLog (
	visitor bigint primary key auto_increment,
	timestamp DATETIME not null,
	id varchar(32) not null
);
