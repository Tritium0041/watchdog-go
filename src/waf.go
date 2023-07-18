package main

import (
	"regexp"
	"strings"
)

// 用于处理文件里的代码
var r, _ = regexp.Compile("eval\\(\\$*\\)" + //eval($_POST['xxx']) eval($_GET['xxx'])
	"|system\\(\\$*\\)" + //system($_POST['xxx']) system($_GET['xxx'])
	"|passthru\\(\\$*\\)" + //passthru($_POST['xxx']) passthru($_GET['xxx'])
	"|exec\\(\\$*\\)" + //exec($_POST['xxx']) exec($_GET['xxx'])
	"|chroot\\(\\$*\\)" + //chroot($_POST['xxx']) chroot($_GET['xxx'])
	"|chgrp\\(\\$*\\)" + //chgrp($_POST['xxx']) chgrp($_GET['xxx'])
	"|chown\\(\\$*\\)" + //chown($_POST['xxx']) chown($_GET['xxx'])
	"|shell_exec\\(\\$*\\)" + //shell_exec($_POST['xxx']) shell_exec($_GET['xxx'])
	"|proc_open\\(\\$*\\)" + //proc_open($_POST['xxx']) proc_open($_GET['xxx'])
	"|proc_get_status\\(\\$*\\)" + //proc_get_status($_POST['xxx']) proc_get_status($_GET['xxx'])
	"|ini_alter\\(\\$*\\)" + //ini_alter($_POST['xxx']) ini_alter($_GET['xxx'])
	"|ini_set\\(\\$*\\)" + //ini_set($_POST['xxx']) ini_set($_GET['xxx'])
	"|ini_restore\\(\\$*\\)" + //ini_restore($_POST['xxx']) ini_restore($_GET['xxx'])
	"|dl\\(\\$*\\)" + //dl($_POST['xxx']) dl($_GET['xxx'])
	"|pfsockopen\\(\\$*\\)" + //pfsockopen($_POST['xxx']) pfsockopen($_GET['xxx'])
	"|popen\\(\\$*\\)" + //popen($_POST['xxx']) popen($_GET['xxx'])
	"|putenv\\(\\$*\\)") //putenv($_POST['xxx']) putenv($_GET['xxx'])

func wafRCE(inputString string) bool {
	// 定义允许的字符和模板标签
	disallowedChars := "startfile|remove|cat|c\\?t|$IFS$9|$IFS|\\ |flag|f\\?\\?g|f\\\\*|\\?\\?\\?|\\?\\?t|c\\?\\?|\\?a\\?" +
		"|unlink|rename|replace|copy|shutil|tempfile|mktemp|dir|chdir|path|walk|listdir|getcwd|getpid" +
		"|getppid|getuid|geteuid|getgid|getegid|getgroups|getlogin|getpgrp|ge|ls|\\." +
		"more|less|head|tail|tac|nl|od|strings|hexdump|xxd|base64|file|stat|wc|du|df|dd|cp|mv|mkdir|rmdir" +
		"|touch|ln|locate|find|which|type|whereis|whatis|alias|unalias|alias|set|export|unset|env|printenv" +
		"|source|history|jobs|bg|fg|kill|killall|pkill|ps|pstree|top|htop|atop|lsof|ss|netstat|ifconfig" +
		"|ip|arp|route|traceroute|ping|nc|telnet|ssh|scp|ftp|sftp|wget|curl|dig|host|nslookup|whois|tcpdump"
	allowedTags := []string{"{{", "}}", "{%", "%}"}

	// 检查输入中是否存在禁止的字符
	if matched, _ := regexp.MatchString(disallowedChars, inputString); matched {
		return false
	}

	// 检查输入中是否存在模板标签
	for _, tag := range allowedTags {
		if strings.Contains(inputString, tag) {
			return false
		}
	}

	// 输入通过了所有检查
	return true
}

func wafsqli(inputString string) bool {
	// 定义允许的字符和模板标签
	disallowedChars := "select|union|from|where|and|or|order|by|limit|offset|group|having|int" +
		"|char|varchar|text|bigint|tinyint|smallint|mediumint|decimal|double|float|date|time|year" +
		"|timestamp|datetime|enum" +
		"|set|binary|varbinary|blob|tinyblob|mediumblob|longblob|bit|bool|boolean|geometry|point" +
		"|linestring|polygon|multipoint|multilinestring|multipolygon|geometrycollection|json|jsonarray" +
		"|jsonobject|jsonschema|regexp|regexp_like|regexp_instr|regexp_substr|regexp_replace|like|not" +
		"|between|in|is|exists|case|when|then|else|'|#|and|or|;|\\.|\\(|\\)|\\*|\\+|,|\\-|\\.|\\/"

	// 检查输入中是否存在禁止的字符
	if matched, _ := regexp.MatchString(disallowedChars, inputString); matched {
		return false
	}

	// 输入通过了所有检查
	return true
}

func wafcode(f string) bool {
	find := r.FindAllString(f, -1)
	if len(find) > 0 {
		//大概有害
		return false
	}
	//大概无害
	return true
}
