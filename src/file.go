package main

import (
	"archive/zip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func loadFiles() {
	db := getdb()
	defer db.Close()
	var dirs []string
	rows, err := db.Query("select siteworkdir from sites")
	checkerr(err)
	for rows.Next() {
		var dir string
		err = rows.Scan(&dir)
		checkerr(err)
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	rows.Close()
	for _, dir := range dirs {
		fileInfos, err := os.ReadDir(dir)
		checkerr(err)
		for _, fi := range fileInfos {
			if strings.HasSuffix(fi.Name(), ".harmful.bak") {
				continue
			}
			filename := dir + "/" + fi.Name()
			if fi.IsDir() {
				dirs = append(dirs, filename)
			} else {
				state, err := db.Prepare("select count(*) from files where filename = ?")
				checkerr(err)
				var count int
				err = state.QueryRow(filename).Scan(&count)
				checkerr(err)
				if count == 0 {
					state, err = db.Prepare("select sitedomain from sites where siteworkdir = ?")
					checkerr(err)
					var sitedomain string
					err = state.QueryRow(dir).Scan(&sitedomain)
					checkerr(err)
					state, err = db.Prepare("insert into files (filename, sitedomain) values (?, ?)")
					checkerr(err)
					_, err = state.Exec(filename, sitedomain)
					checkerr(err)
					if !checkeVulnableFile(filename) {
						state, err := db.Prepare("insert into harmfulfiles (filename,rootdir,sitedomain) values (?,?,?)")
						checkerr(err)
						_, err = state.Exec(filename, dir, sitedomain)
						checkerr(err)
						file, err := os.ReadFile(filename)
						checkerr(err)
						results := strings.Split(string(file), "\n")
						for linenum, result := range results {
							findline := r.FindAllString(result, -1)
							if len(findline) > 0 {
								state, err := db.Prepare("insert into harmfulcodes (filename,linenum,code) values (?,?,?)")
								checkerr(err)
								_, err = state.Exec(filename, linenum+1, result)
								checkerr(err)
							}
						}
					}
					oldname := filename
					newname := filename + ".harmful.bak"
					os.Rename(oldname, newname)
				}
			}
		}
	}
}

func backupFiles(path string, site string) {
	outputPath := "./backup/" + site + ".zip"
	zipfile, err := os.Create(outputPath)
	checkerr(err)
	defer zipfile.Close()
	zipWriter := zip.NewWriter(zipfile)
	defer zipWriter.Close()
	err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		file, err := os.Open(filePath)
		checkerr(err)
		defer file.Close()
		if !info.IsDir() {
			// 获取文件在ZIP中的相对路径
			relativePath, err := filepath.Rel(path, filePath)
			checkerr(err)
			// 在ZIP中创建文件
			f, err := zipWriter.Create(relativePath)
			checkerr(err)
			// 将文件内容拷贝到ZIP中
			_, err = io.Copy(f, file)
			checkerr(err)
		}
		return nil
	})
	checkerr(err)
}

func checkFilesExist() {
	db := getdb()
	defer db.Close()
	rows, err := db.Query("select filename,siteworkdir,sitedomain from files")
	checkerr(err)
	for rows.Next() {
		var (
			filename    string
			siteworkdir string
			sitedomain  string
		)
		err = rows.Scan(&filename, &siteworkdir, &sitedomain)
		checkerr(err)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			cmd := exec.Command("unzip", "./backup/"+sitedomain+".zip", "-d", "/tmp/"+sitedomain)
			err := cmd.Run()
			checkerr(err)
			tmpfilename := "/tmp/" + sitedomain + "/" + strings.Replace(filename, siteworkdir, "", 1)
			cmd = exec.Command("mv", tmpfilename, filename)
			err = cmd.Run()
			checkerr(err)
			cmd = exec.Command("rm", "-rf", "/tmp/"+sitedomain)
			err = cmd.Run()
			checkerr(err)
		}
	}
	rows.Close()
}

func checkeVulnableFile(filePath string) bool {
	file, err := os.ReadFile(filePath)
	checkerr(err)
	return wafcode(string(file))
}

func checkfilesmain() {
	timer := time.NewTicker(time.Second * 60)
	for {
		select {
		case <-timer.C:
			loadFiles()
			checkFilesExist()
		}
	}
}
