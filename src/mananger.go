package main

import (
	"crypto/sha1"
	"database/sql"
	"embed"
	"encoding/json"
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
		_, err = db.Exec("create table HTTPtraffic (id integer not null primary key autoincrement, sourceIP text not null, requestHost text not null, requestPath text not null, requestMethod text not null, requestTime integer not null,requestContent text not null,requestQuery text not null,requestHeader text not null)")
		checkerr(err)
		_, err = db.Exec("create table sites (id integer not null primary key autoincrement,host text not null,siteWorkDir text not null,rule text not null,sqlEnabled bool not null,rceEnabled bool not null)")
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
	} else if strings.Contains(requestPath, "admin") {
		mgrCheckLogin(w, r, db)
	}
}

func mgrCheckLogin(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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
	requestPath := r.URL.Path
	if requestPath == "/admin" {
		mgrAdmin(w, r)
	} else if strings.HasPrefix(requestPath, "/api") {
		if requestPath == "/api/admin/blacklist" {
			apiBlacklist(w, r, db)
		} else if requestPath == "/api/admin/blacklist/num" {
			apiBlacklistNum(w, r, db)
		} else if requestPath == "/api/admin/blacklist/delete" {
			apideleteBlacklist(w, r, db)
		}
		if requestPath == "/api/admin/requests" {
			apiRequests(w, r, db)
		} else if requestPath == "/api/admin/requests/num" {
			apiRequestsNum(w, r, db)
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
	page, err := f.ReadFile("app/admin.html")
	checkerr(err)
	w.Write(page)

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
	fmt.Printf(num)
	numint, err := strconv.Atoi(num)
	checkerr(err)
	//num是页数，取出10(num-1)-10num的IP
	numint = numint * 10
	rows, err := db.Query("select IP from IPblackList limit ?,?", numint-10, numint)
	defer rows.Close()
	var IP []string
	for rows.Next() {
		var ip string
		err = rows.Scan(&ip)
		checkerr(err)
		IP = append(IP, ip)
	}
	//将IP转为json
	IPjson, err := json.Marshal(IP)
	checkerr(err)
	w.Write(IPjson)
}

func apideleteBlacklist(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	IP := r.FormValue("ip")
	fmt.Printf(IP)
	state, err := db.Prepare("delete from IPblackList where IP=?")
	checkerr(err)
	_, err = state.Exec(IP)
	checkerr(err)
	w.Write([]byte("Success"))
}

func apiRequestsNum(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.Query("select count(*) from HTTPtraffic")
	checkerr(err)
	defer rows.Close()
	var num int
	for rows.Next() {
		err = rows.Scan(&num)
		checkerr(err)
	}
	w.Write([]byte(strconv.Itoa(num)))
}
func apiRequests(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	num := r.FormValue("num")
	//将num转为int
	fmt.Printf(num)
	numint, err := strconv.Atoi(num)
	checkerr(err)
	//num是页数，取出10(num-1)-10num的IP
	numint = numint * 10
	rows, err := db.Query("select id,sourceIP,requestHost,requestPath,requestMethod,requestTime,requestContent,requestquery,requestHeader from HTTPtraffic limit ?,?", numint-10, numint)
	defer rows.Close()
	var (
		ID             []int
		sourceIP       []string
		requestHost    []string
		requestPath    []string
		requestMethod  []string
		requestTime    []int
		requestContent []string
		requestQuery   []string
		requestHeader  []string
	)
	for rows.Next() {
		var (
			id      int
			ip      string
			host    string
			path    string
			method  string
			time    int
			content string
			query   string
			header  string
		)
		err = rows.Scan(&id, &ip, &host, &path, &method, &time, &content, &query, &header)
		checkerr(err)
		ID = append(ID, id)
		sourceIP = append(sourceIP, ip)
		requestHost = append(requestHost, host)
		requestPath = append(requestPath, path)
		requestMethod = append(requestMethod, method)
		requestTime = append(requestTime, time)
		requestContent = append(requestContent, content)
		requestQuery = append(requestQuery, query)
		requestHeader = append(requestHeader, header)

	}
	//转为json
	requests := make(map[string]interface{})
	requests["id"] = ID
	requests["sourceIP"] = sourceIP
	requests["requestHost"] = requestHost
	requests["requestPath"] = requestPath
	requests["requestMethod"] = requestMethod
	requests["requestTime"] = requestTime
	requests["requestContent"] = requestContent
	requests["requestQuery"] = requestQuery
	requests["requestHeader"] = requestHeader
	requestsjson, err := json.Marshal(requests)
	checkerr(err)
	w.Write(requestsjson)
}
