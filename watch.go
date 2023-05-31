package sshHostsDeny

import (
	"github.com/caryxiao/go-zlog"
	"github.com/hpcloud/tail"
	"regexp"
	"strings"
)

func Watch(config CmdConfig) (err error) {
	err = config.validate()
	if err != nil {
		return
	}

	// whence
	// 0 = 文件开始位置, 1 = 当前位置, 2 = 文件结尾处
	t, err := tail.TailFile(config.SecureFile, tail.Config{
		Follow:   true,
		Location: &tail.SeekInfo{Whence: 2},
		Logger:   zlog.Logger, //使用我们自己的logger
	})

	if err != nil {
		zlog.Logger.Error(err.Error())
		return
	}

	denyFile := config.DenyFile

	hs, err := getSystemHostsDeny(denyFile)

	if err != nil {
		zlog.Logger.Error(err)
	}

	zlog.Logger.Debugf("hosts list: %+v", hs)

	if err != nil {
		zlog.Logger.Error(err.Error())
	}

	// use for PamCheck
	pattern := `^.*pam_unix\(sshd:auth\)\:.*rhost=([^\s]*).*$`
	reg := regexp.MustCompile(pattern)
	for line := range t.Lines {
		lineText := strings.TrimSpace(line.Text)

		// 登录成功删除计数记录
		removeRecordHostWhenLoginSuccessfully(lineText, hs)

		// 原策略
		if config.CheckStyle == "pam" {
            PamCheck(lineText, reg, hs, config, denyFile)
		} else if config.CheckStyle == "password" {
            // 按判断密码登录策略
		    AddRecordHostWhenFailedPassword(lineText, hs, config, denyFile)
		}
	}
	return
}

func AddRecordHostWhenFailedPassword(lineText string, hs hosts, config CmdConfig, denyFile string)  {
	mark := "]: Failed password for"
	idx := strings.Index(lineText, mark)
	if idx != -1 && strings.Contains(lineText, " sshd[") {
		subLineText := lineText[idx:]
		tokens := strings.Split(subLineText, " ")
		ip := tokens[6]

		if !hs.FindKey(ip) {
			rdhs := hs.GetRecordHost(ip)
			if rdhs.Cnt < config.SshLoginFailCnt {
				hs.AddRecordHost(host{HType: "sshd", Ip: ip})
				zlog.Logger.Debugf("add, type: %s, ip: %s, cnt: %d", "sshd", ip, rdhs.Cnt)
			} else {
				zlog.Logger.Debugf("write, type: %s, ip: %s, cnt: %d", rdhs.HType, rdhs.Ip, rdhs.Cnt)
				err := WriteFile(denyFile, rdhs.HType+":"+rdhs.Ip)
				if err != nil {
					zlog.Logger.Errorf("write error: %s", err)
				}
				hs.add(rdhs.host)
				hs.DelRecordHost(rdhs.host)
				zlog.Logger.Debugf("write %+v", hs)
			}
		}
		zlog.Logger.Debugf("matched %+v", hs)
	}
}

func removeRecordHostWhenLoginSuccessfully(lineText string, hs hosts) {
	mark := "Accepted password for"
	idx := strings.Index(lineText, mark)
	if idx != -1 && strings.Contains(lineText, " sshd[") {
		subLineText := lineText[idx:]
		tokens := strings.Split(subLineText, " ")
		ip := tokens[5]
		user := tokens[3]

		delete(hs.RecordHost, ip)
		zlog.Logger.Infof("user %s login ok from %s", user, ip)
	}
}

// 这是原作者的判断方式
func PamCheck(lineText string, reg *regexp.Regexp, hs hosts, config CmdConfig, denyFile string)  {
	matched := reg.FindStringSubmatch(lineText)
		if len(matched) > 0 {
			ip := matched[1]
			if !hs.FindKey(ip) {
				rdhs := hs.GetRecordHost(ip)
				if rdhs.Cnt < config.SshLoginFailCnt {
					hs.AddRecordHost(host{HType: "sshd", Ip: ip})
					zlog.Logger.Debugf("add, type: %s, ip: %s, cnt: %d", "sshd", ip, rdhs.Cnt)
				} else {
					zlog.Logger.Debugf("write, type: %s, ip: %s, cnt: %d", rdhs.HType, rdhs.Ip, rdhs.Cnt)
					err := WriteFile(denyFile, rdhs.HType+":"+rdhs.Ip)
					if err != nil {
						zlog.Logger.Errorf("write error: %s", err)
					}
					hs.add(rdhs.host)
					hs.DelRecordHost(rdhs.host)
					zlog.Logger.Debugf("write %+v", hs)
				}
			}
			zlog.Logger.Debugf("matched %+v", hs)
		}
}
