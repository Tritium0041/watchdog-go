package main

import "net/http"

func handleHttp(w http.ResponseWriter, r *http.Request) {
	// 获取请求的host
	requestHost := r.Host
	if requestHost == self_host {
		// 如果请求的host为SELF_HOST，则发送处理管理界面
		mananger(w, r)
	}

}
