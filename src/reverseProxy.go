package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func handleHttp(w http.ResponseWriter, r *http.Request) {
	// 获取请求的host
	requestHost := r.Host
	if requestHost == self_host {
		// 如果请求的host为SELF_HOST，则发送处理管理界面
		mananger(w, r)
	} else {
		recordTraffic(r)
		//TODO 记录后开始处理请求 我先去把webui写了

	}

}
func recordTraffic(r *http.Request) {
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
		db.Close()
	}
	// 打开数据库
	db, err := sql.Open("sqlite3", sqlite_file)
	defer db.Close()
	checkerr(err)
	requestPath := r.URL.Path
	requestMethod := r.Method
	var requestContent string
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	requestContent = buf.String()
	// 获取请求的host
	requestHost := r.Host
	// 获取请求的IP
	requestIP := r.RemoteAddr
	// 获取请求的时间
	requestTime := time.Now().Unix()
	requestQuery := r.URL.RawQuery
	requestHeader, err := json.Marshal(r.Header)
	checkerr(err)
	fmt.Printf("requestIP: %s\nrequestHost: %s\nrequestPath: %s\nrequestMethod: %s\nrequestTime: %d\nrequestContent: %s\nrequestQuery: %s\nrequestHeader: %s\n", requestIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader)
	_, err = db.Exec("insert into HTTPtraffic (sourceIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader) values (?, ?, ?, ?, ?, ?, ?, ?)", requestIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader)
	checkerr(err)
}
