package main

import (
	"database/sql"
	"embed"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
	"os"
)

//go:embed app/*
var f embed.FS

func mananger(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(sqlite_file)
	if err != nil {
		// 如果数据库不存在，则创建数据库
		db, err := sql.Open("sqlite3", sqlite_file)
		checkerr(err)
		_, err = db.Exec("create table user (id integer not null primary key autoincrement, username text not null, password text not null)")
		checkerr(err)
		_, err = db.Exec("insert into user (username, password) values ('admin', 'd033e22ae348aeb5660fc2140aec35850c4da997')")
		checkerr(err)
		db.Close()

	}
	// 打开数据库
	db, err := sql.Open("sqlite3", sqlite_file)
	defer db.Close()
	checkerr(err)
	requestPath := r.URL.Path
	if requestPath == "/" || requestPath == "/blackicon.png" {
		mgrStatic(w, r, requestPath)
	}
}

func mgrStatic(w http.ResponseWriter, r *http.Request, Path string) {
	//如果requestPath为/，则发送index
	if Path == "/" {
		Path = "/index.html"
	}
	fmt.Printf("app%s\n", Path)
	page, err := f.ReadFile("app" + Path)
	checkerr(err)
	w.Write(page)

}
