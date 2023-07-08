package main

import (
	"crypto/sha1"
	"database/sql"
	"embed"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
	"os"
	"strconv"
	"strings"
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
		_, err = db.Exec("create table IPblackList (id integer not null primary key autoincrement, IP text not null)")
		checkerr(err)

		db.Close()

	}
	// 打开数据库
	db, err := sql.Open("sqlite3", sqlite_file)
	defer db.Close()
	checkerr(err)
	requestPath := r.URL.Path
	requestMethod := r.Method
	if requestPath == "/" || strings.HasPrefix(requestPath, "/static") {
		mgrStatic(w, r, requestPath)
	} else if requestPath == "/submitToken" && requestMethod == "POST" {
		mgrAuth(w, r, db)
	} else if requestPath == "/admin" {
		mgrAdmin(w, r)
	} else if strings.HasPrefix(requestPath, "/api") {
		if requestPath == "/api/blacklist" {
			apiBlacklist(w, r, db)
		} else if requestPath == "/api/blacklistNum" {
			apiBlacklistNum(w, r, db)
		}
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

func mgrAuth(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// 获取请求的host
	//解析post内容
	r.ParseForm()
	Token := r.FormValue("Token")
	fmt.Printf("Token:%s\n", Token)
	//对Token计算sha1
	sha1er := sha1.New()
	sha1er.Write([]byte(Token))
	hashedtoken := sha1er.Sum(nil)
	//查询数据库
	rows, err := db.Query("select username from user where password=?", fmt.Sprintf("%x", hashedtoken))
	checkerr(err)
	defer rows.Close()
	var username string
	for rows.Next() {
		err = rows.Scan(&username)
		checkerr(err)
	}
	if username != "" {
		//如果数据库中存在对应的Token，则发送管理界面
		fmt.Printf("login success\n")
		jwt, err := GenerateJWT(username)
		checkerr(err)
		w.Header().Set("Set-Cookie", fmt.Sprintf("jwt=%s;path=/", jwt))
		w.Write([]byte("Success"))
	} else {
		//如果数据库中不存在对应的Token，则发送登录界面
		fmt.Printf("login failed")
		w.Write([]byte("Failed"))
	}
}

func mgrAdmin(w http.ResponseWriter, r *http.Request) {
	jwt, err := r.Cookie("jwt")
	if err != nil {
		w.Write([]byte("403 Forbidden"))
		return
	}
	_, err = ParseJWT(jwt.Value)
	if err != nil {
		w.Write([]byte("403 Forbidden"))
		return
	}
	w.Write([]byte("admin"))

}

func apiBlacklistNum(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.Query("select count(*) from IPblackList")
	checkerr(err)
	defer rows.Close()
	var num int
	for rows.Next() {
		err = rows.Scan(&num)
		checkerr(err)
	}
	w.Write([]byte(strconv.Itoa(num)))
}

func apiBlacklist(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	num := r.FormValue("num")
	//将num转为int
	numint, err := strconv.Atoi(num)
	checkerr(err)
	//num是页数，取出10(num-1)-10num的IP
	rows, err := db.Query("select IP from IPblackList limit ?,?", numint, numint+10)
	defer rows.Close()
	var IP []string
	for rows.Next() {
		var ip string
		err = rows.Scan(&ip)
		checkerr(err)
		IP = append(IP, ip)
	}
	//将IP转为json
	w.Write([]byte("[" + strings.Join(IP, ",") + "]"))
}
