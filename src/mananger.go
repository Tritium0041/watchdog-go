package main

import (
	"crypto/sha1"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

//go:embed app/*
var f embed.FS

func mananger(w http.ResponseWriter, r *http.Request) {
	db := getdb()
	defer db.Close()
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
		} else if requestPath == "/api/admin/blacklist/add" {
			apiAddBlacklist(w, r, db)
		}
		if requestPath == "/api/admin/requests" {
			apiRequests(w, r, db)
		} else if requestPath == "/api/admin/requests/num" {
			apiRequestsNum(w, r, db)
		}
		if requestPath == "/api/admin/sites" {
			apiSites(w, r, db)
		} else if requestPath == "/api/admin/sites/add" {
			apiAddSite(w, r, db)
		} else if requestPath == "/api/admin/sites/delete" {
			apideleteSite(w, r, db)
		} else if requestPath == "/api/admin/sites/rules" {
			apiSiteRules(w, r, db)
		} else if requestPath == "/api/admin/sites/rules/add" {
			apiAddRules(w, r, db)
		} else if requestPath == "/api/admin/sites/rules/delete" {
			apideleteRule(w, r, db)
		}
		if requestPath == "/api/admin/harmfulfiles/num" {
			apiharmfulfilesNum(w, r, db)
		} else if requestPath == "/api/admin/harmfulfiles" {
			apiHarmfulfiles(w, r, db)
		} else if requestPath == "/api/admin/harmfulfiles/download" {
			downloadFile(w, r, db)
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
	state, err := db.Prepare("select username from user where password=?")
	checkerr(err)
	rows, err := state.Query(fmt.Sprintf("%x", hashedtoken))
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
	state, err := db.Prepare("select IP from IPblackList limit ?,10")
	checkerr(err)
	rows, err := state.Query(numint - 10)
	checkerr(err)
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

func apiAddBlacklist(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	IP := r.FormValue("ip")
	fmt.Printf(IP)
	state, err := db.Prepare("insert into IPblackList(IP) values(?)")
	checkerr(err)
	_, err = state.Exec(IP)
	checkerr(err)
	w.Write([]byte("Success"))
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
	state, err := db.Prepare("select id,sourceIP,requestHost,requestPath,requestMethod,requestTime,requestContent,requestquery,requestHeader from HTTPtraffic limit ?,10")
	checkerr(err)
	rows, err := state.Query(numint - 10)
	checkerr(err)
	//rows, err := db.Query("select id,sourceIP,requestHost,requestPath,requestMethod,requestTime,requestContent,requestquery,requestHeader from HTTPtraffic limit ?,?", numint-10, numint)
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

func apiSites(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	row, err := db.Query("select sitedomain from sites")
	checkerr(err)
	defer row.Close()
	var sites []string
	for row.Next() {
		var site string
		err = row.Scan(&site)
		checkerr(err)
		sites = append(sites, site)
	}
	sitesjson, err := json.Marshal(sites)
	checkerr(err)
	w.Write(sitesjson)
}

func apiSiteRules(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	domain := r.FormValue("domain")
	state, err := db.Prepare("select id,host,siteworkdir,sitedomain,rule,sqlenabled,rceenabled from sites where sitedomain=?")
	checkerr(err)
	row, err := state.Query(domain)
	checkerr(err)
	defer row.Close()
	var (
		id          int
		host        string
		siteworkdir string
		sitedomain  string
		rule        string
		sqlenabled  bool
		rceenabled  bool
	)
	for row.Next() {
		err = row.Scan(&id, &host, &siteworkdir, &sitedomain, &rule, &sqlenabled, &rceenabled)
		checkerr(err)
	}
	siterules := make(map[string]interface{})
	siterules["id"] = id
	siterules["host"] = host
	siterules["siteworkdir"] = siteworkdir
	siterules["sitedomain"] = sitedomain
	siterules["rules"] = rule
	siterules["sqlenabled"] = sqlenabled
	siterules["rceenabled"] = rceenabled
	siterulesjson, err := json.Marshal(siterules)
	checkerr(err)
	w.Write(siterulesjson)
}

func apiAddRules(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	domain := r.FormValue("domain")
	sqli := r.FormValue("sqli")
	rce := r.FormValue("rce")
	rule := r.FormValue("rule")
	ruleType := r.FormValue("type")
	//先处理sqli和rce
	var sqlenabled bool
	var rceenabled bool
	if sqli == "true" {
		sqlenabled = true
	} else {
		sqlenabled = false
	}
	if rce == "true" {
		rceenabled = true
	} else {
		rceenabled = false
	}
	state, err := db.Prepare("update sites set sqlenabled=?,rceenabled=? where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(sqlenabled, rceenabled, domain)
	checkerr(err)
	//再处理rule
	if rule == "" {
		w.Write([]byte("Success"))
		return
	}
	state, err = db.Prepare("select rule from sites where sitedomain=?")
	checkerr(err)
	row, err := state.Query(domain)
	defer row.Close()
	var oldrule string
	for row.Next() {
		err = row.Scan(&oldrule)
		checkerr(err)
	}
	var oldrules []string
	json.Unmarshal([]byte(oldrule), &oldrules)
	newRule := make(map[string]string)
	newRule["type"] = ruleType
	newRule["rule"] = rule
	newRuleJson, err := json.Marshal(newRule)
	oldrules = append(oldrules, string(newRuleJson))
	newrulesjson, err := json.Marshal(oldrules)
	checkerr(err)
	state, err = db.Prepare("update sites set rule=? where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(string(newrulesjson), domain)
	checkerr(err)
	w.Write([]byte("Success"))
}

func apideleteRule(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	domain := r.FormValue("domain")
	rule := r.FormValue("rule")
	state, err := db.Prepare("select rule from sites where sitedomain=?")
	checkerr(err)
	row, err := state.Query(domain)
	defer row.Close()
	var oldrule string
	for row.Next() {
		err = row.Scan(&oldrule)
		checkerr(err)
	}
	var oldrules []string
	json.Unmarshal([]byte(oldrule), &oldrules)
	var newrules []string
	for _, v := range oldrules {
		var rulemap map[string]string
		json.Unmarshal([]byte(v), &rulemap)
		if rulemap["rule"] != rule {
			newrules = append(newrules, v)
		}
	}
	newrulesjson, err := json.Marshal(newrules)
	fmt.Printf(string(newrulesjson))
	checkerr(err)
	state, err = db.Prepare("update sites set rule=? where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(string(newrulesjson), domain)
	checkerr(err)
	w.Write([]byte("Success"))
}

func apiAddSite(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	sitedomain := r.FormValue("domain")
	siteworkdir := r.FormValue("workdir")
	backupFiles(siteworkdir, sitedomain)
	host := r.FormValue("url")
	var (
		sqlenabled bool   = true
		rceenabled bool   = true
		rule       string = "[]"
	)
	state, err := db.Prepare("insert into sites(host,siteworkdir,sitedomain,rule,sqlenabled,rceenabled) values(?,?,?,?,?,?)")
	checkerr(err)
	_, err = state.Exec(host, siteworkdir, sitedomain, rule, sqlenabled, rceenabled)
	checkerr(err)
	w.Write([]byte("Success"))
}
func apideleteSite(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	domain := r.FormValue("domain")
	state, err := db.Prepare("delete from sites where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(domain)
	checkerr(err)
	state, err = db.Prepare("delete from harmfulcodes where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(domain)
	checkerr(err)
	state, err = db.Prepare("delete from harmfulfiles where sitedomain=?")
	checkerr(err)
	_, err = state.Exec(domain)
	checkerr(err)
	w.Write([]byte("Success"))
}

func apiharmfulfilesNum(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	row, err := db.Query("select count(*) from harmfulfiles")
	checkerr(err)
	defer row.Close()
	var num int
	for row.Next() {
		err = row.Scan(&num)
		checkerr(err)
	}
	w.Write([]byte(strconv.Itoa(num)))
}

func apiHarmfulfiles(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	page := r.FormValue("page")
	numint, err := strconv.Atoi(page)
	checkerr(err)
	numint = numint * 10
	state, err := db.Prepare("select * from harmfulcodes limit ?,10")
	checkerr(err)
	row, err := state.Query(numint - 10)
	var (
		id       []int
		filename []string
		linenum  []int
		content  []string
		sites    []string
	)
	for row.Next() {
		var (
			idInt          int
			filenameString string
			linenumInt     int
			contentString  string
		)
		err = row.Scan(&idInt, &filenameString, &linenumInt, &contentString)
		checkerr(err)
		id = append(id, idInt)
		filename = append(filename, filenameString)
		linenum = append(linenum, linenumInt)
		encoding := base64.Encoding{}
		contentString = encoding.EncodeToString([]byte(contentString))
		content = append(content, contentString)
	}
	state, err = db.Prepare("select sitedomain from harmfulfiles where filename=?")
	checkerr(err)
	for _, v := range filename {
		var sitedomain string
		err = state.QueryRow(v).Scan(&sitedomain)
		checkerr(err)
		sites = append(sites, sitedomain)
	}
	var data = make(map[string]interface{})
	data["id"] = id
	data["filename"] = filename
	data["linenum"] = linenum
	data["content"] = content
	data["sites"] = sites
	jsondata, err := json.Marshal(data)
	checkerr(err)
	w.Write(jsondata)
}

func downloadFile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()
	id := r.FormValue("id")
	state, err := db.Prepare("select filename from harmfulcodes where id=?")
	checkerr(err)
	row, err := state.Query(id)
	defer row.Close()
	var filename string
	for row.Next() {
		err = row.Scan(&filename)
		checkerr(err)
	}
	file, err := os.ReadFile(filename)
	checkerr(err)
	w.Header().Set("Content-Type", "application/octet-stream")
	pureFileName := path.Base(filename)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", pureFileName))
	w.Write(file)

}
