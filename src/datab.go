package main

import (
	"database/sql"
	"os"
)

func getdb() (db *sql.DB) {
	_, err := os.Stat(sqlite_file)
	if err != nil {
		// 如果数据库不存在，则创建数据库
		db, err := sql.Open("sqlite3", sqlite_file)
		checkerr(err)
		_, err = db.Exec("create table user (id integer not null primary key autoincrement, username text not null, password text not null)")
		checkerr(err)
		_, err = db.Exec("insert into user (username, password) values ('admin', 'd033e22ae348aeb5660fc2140aec35850c4da997')")
		checkerr(err)
		_, err = db.Exec("create table IPblackList (id integer not null primary key autoincrement, IP text not null)")
		checkerr(err)
		_, err = db.Exec("create table HTTPtraffic (id integer not null primary key autoincrement, sourceIP text not null, requestHost text not null, requestPath text not null, requestMethod text not null, requestTime integer not null,requestContent text not null,requestQuery text not null,requestHeader text not null)")
		checkerr(err)
		_, err = db.Exec("create table sites (id integer not null primary key autoincrement,host text not null,siteworkdir text,sitedomain text not null,rule text,sqlenabled bool not null,rceenabled bool not null)")
		checkerr(err)
		_, err = db.Exec("create table files (id integer not null primary key autoincrement,filename text not null,rootdir text not null,sitedomain text not null)")
		checkerr(err)
		_, err = db.Exec("create table harmfulfiles (id integer not null primary key autoincrement,filename text not null,rootdir text not null,sitedomain text not null)")
		checkerr(err)
		_, err = db.Exec("create table harmfulcodes (id integer not null primary key autoincrement,filename text not null,linenum integer not null,content text not null)")
		checkerr(err)
		db.Close()
	}
	db, err = sql.Open("sqlite3", sqlite_file)
	checkerr(err)
	return db
}
