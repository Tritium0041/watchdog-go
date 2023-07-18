package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
		handleRequest(w, r)

	}

}
func recordTraffic(r *http.Request) {
	db := getdb()
	defer db.Close()
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
	//fmt.Printf("requestIP: %s\nrequestHost: %s\nrequestPath: %s\nrequestMethod: %s\nrequestTime: %d\nrequestContent: %s\nrequestQuery: %s\nrequestHeader: %s\n", requestIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader)
	_, err = db.Exec("insert into HTTPtraffic (sourceIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader) values (?, ?, ?, ?, ?, ?, ?, ?)", requestIP, requestHost, requestPath, requestMethod, requestTime, requestContent, requestQuery, requestHeader)
	checkerr(err)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	db := getdb()
	defer db.Close()
	host := r.Host
	state, err := db.Prepare("select count(*) from sites where sitedomain = ?")
	checkerr(err)
	var count int
	err = state.QueryRow(host).Scan(&count)
	checkerr(err)
	if count == 0 {
		// 如果数据库中没有这个域名的记录，则返回404
		w.WriteHeader(404)
	} else {
		if !filterRequest(r, db) {
			genshin, err := f.ReadFile("app/genshin.txt")
			checkerr(err)
			w.Write(genshin)
			return
		}
		DestContent(w, r)
	}

}

func filterRequest(r *http.Request, db *sql.DB) bool {
	host := r.Host
	//Header, err := json.Marshal(r.Header)
	//checkerr(err)
	Path := r.URL.Path
	Query := r.URL.RawQuery
	sourceIP := strings.Split(r.RemoteAddr, ":")[0]
	row, err := db.Query("select count(*) from IPblackList where IP = ?", sourceIP)
	checkerr(err)
	var count int
	for row.Next() {
		err = row.Scan(&count)
		checkerr(err)
	}
	if count != 0 {
		return false
	}

	var requestContent string
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	requestContent = buf.String()
	state, err := db.Prepare("select rule,sqlenabled,rceenabled from sites where sitedomain = ?")
	checkerr(err)
	var (
		sqlenabled bool
		rceenabled bool
		rule       string
	)
	err = state.QueryRow(host).Scan(&rule, &sqlenabled, &rceenabled)
	checkerr(err)
	if sqlenabled {
		if !(wafsqli(Query + requestContent)) {
			return false
		}
	}
	if rceenabled {
		if !(wafRCE(Query + requestContent)) {
			return false
		}
	}
	var rules []string
	err = json.Unmarshal([]byte(rule), &rules)
	checkerr(err)
	for _, certainrule := range rules {
		var rul map[string]string
		err = json.Unmarshal([]byte(certainrule), &rul)
		checkerr(err)
		fmt.Println(rul)
		switch {
		case rul["type"] == "prefix":
			if strings.HasPrefix(Path, rul["rule"]) {
				return false
			}
		case rul["type"] == "suffix":
			if strings.HasSuffix(Path, rul["rule"]) {
				return false
			}
		case rul["type"] == "contains":
			if strings.Contains(Path, rul["rule"]) {
				return false
			}
		}

	}
	return true
}

func DestContent(w http.ResponseWriter, r *http.Request) {
	db := getdb()
	defer db.Close()
	host := r.Host
	state, err := db.Prepare("select host from sites where sitedomain = ?")
	checkerr(err)
	var desthost string
	err = state.QueryRow(host).Scan(&desthost)
	checkerr(err)
	Method := r.Method
	Path := r.URL.Path
	Query := r.URL.RawQuery
	var requestContent string
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	requestContent = buf.String()
	checkerr(err)
	var desturl string
	if Query == "" {
		desturl = "http://" + desthost + Path
	} else {
		desturl = "http://" + desthost + Path + "?" + Query
	}
	fmt.Println(desturl)
	client := &http.Client{}
	req, err := http.NewRequest(Method, desturl, strings.NewReader(requestContent))
	checkerr(err)
	for k, v := range r.Header {
		req.Header.Set(k, v[0])
	}
	resp, err := client.Do(req)
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
