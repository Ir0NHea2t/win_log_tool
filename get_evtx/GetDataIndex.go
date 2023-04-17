package get_evtx

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func GetEvtx() ([]map[string]string, []map[string]string, []map[string]string, []map[string]string, string, string, string, string, string, string) {
	windowsEvtxFile := "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
	var offset int64
	offset = 0

	var loginSuccessSlice []*evtx.GoEvtxMap //4624登录成功
	var loginFailSlice []*evtx.GoEvtxMap    //4625登录失败
	var usersOperateSlice []*evtx.GoEvtxMap //4720创建用户 4724重置账号密码 4732添加到组   4733从组中删除用户 4726删除用户账户
	var clearHistorySlice []*evtx.GoEvtxMap //1102 日志清除

	//获取到evtx数据
	f, err := os.Open(windowsEvtxFile)
	if err != nil {
		fmt.Println("文件打开失败")
	}
	defer f.Close()

	f.Seek(offset, os.SEEK_SET)

	evtxf, _ := evtx.New(f)
	for event := range evtxf.FastEvents() {
		//事件id
		eventID := event.EventID()
		//fmt.Println(eventID)

		if strconv.FormatInt(eventID, 10) == "4624" {
			loginSuccessSlice = append(loginSuccessSlice, event)
		} else if strconv.FormatInt(eventID, 10) == "4625" {
			loginFailSlice = append(loginFailSlice, event)
		} else if strconv.FormatInt(eventID, 10) == "4720" || strconv.FormatInt(eventID, 10) == "4724" || strconv.FormatInt(eventID, 10) == "4732" || strconv.FormatInt(eventID, 10) == "4733" || strconv.FormatInt(eventID, 10) == "4726" {
			usersOperateSlice = append(usersOperateSlice, event)
		} else if strconv.FormatInt(eventID, 10) == "1102" {
			clearHistorySlice = append(clearHistorySlice, event)
		}

	}

	var loginSuccessMapSlice = make([]map[string]string, len(loginSuccessSlice)) //保存4624结果
	var loginFailMapSlice = make([]map[string]string, len(loginFailSlice))       //保存4625
	var usersOperateMapSlice = make([]map[string]string, len(usersOperateSlice)) //保存用户变动
	var clearHistoryMapSlice = make([]map[string]string, len(clearHistorySlice)) //保存用户变动

	typeIDpath := evtx.Path("/Event/EventData/LogonType")
	ipAddressPath := evtx.Path("/Event/EventData/IpAddress")
	usernamePath := evtx.Path("/Event/EventData/TargetUserName")
	workstationPath := evtx.Path("/Event/EventData/WorkstationName")
	subjectUsernamePath := evtx.Path("/Event/EventData/SubjectUserName")
	subjectDomainPath := evtx.Path("/Event/EventData/SubjectDomainName")
	processNamePath := evtx.Path("/Event/EventData/ProcessName")

	//处理信息
	fmt.Println("------------------------登录成功-------------------------")
	for k, event := range loginSuccessSlice {
		//fmt.Println(event)
		loginSuccessMapSlice[k] = make(map[string]string)
		//时间
		eventTime := event.TimeCreated().Format(http.TimeFormat)
		loginSuccessMapSlice[k]["time"] = eventTime
		//事件id
		eventID := event.EventID()
		loginSuccessMapSlice[k]["eventID"] = strconv.FormatInt(eventID, 10)
		//事件类型id
		typeID, _ := event.GetString(&typeIDpath)
		loginSuccessMapSlice[k]["typeID"] = typeID
		//ip地址
		eventIp, _ := event.GetString(&ipAddressPath)
		loginSuccessMapSlice[k]["eventIp"] = eventIp
		//用户名
		eventUsername, _ := event.GetString(&usernamePath)
		loginSuccessMapSlice[k]["eventUsername"] = eventUsername
		//workstation
		eventWorkstation, _ := event.GetString(&workstationPath)
		loginSuccessMapSlice[k]["eventWorkstation"] = eventWorkstation
		//subjectUsername
		eventSubjectUsername, _ := event.GetString(&subjectUsernamePath)
		loginSuccessMapSlice[k]["eventSubjectUsername"] = eventSubjectUsername
		//subjectDomain
		eventSubjectDomain, _ := event.GetString(&subjectDomainPath)
		loginSuccessMapSlice[k]["eventSubjectDomain"] = eventSubjectDomain
		//进程名
		eventProcessName, _ := event.GetString(&processNamePath)
		loginSuccessMapSlice[k]["eventProcessName"] = eventProcessName
	}
	//处理信息
	fmt.Println("------------------------登录失败-------------------------")
	for k, event := range loginFailSlice {
		//fmt.Println(event)
		loginFailMapSlice[k] = make(map[string]string)
		//事件时间
		eventTime := event.TimeCreated().Format(http.TimeFormat)
		loginFailMapSlice[k]["time"] = eventTime
		//事件id
		eventID := event.EventID()
		loginFailMapSlice[k]["eventID"] = strconv.FormatInt(eventID, 10)
		//事件类型id
		typeID, _ := event.GetString(&typeIDpath)
		loginFailMapSlice[k]["typeID"] = typeID
		//ip地址
		eventIp, _ := event.GetString(&ipAddressPath)
		loginFailMapSlice[k]["eventIp"] = eventIp
		//用户名
		eventUsername, _ := event.GetString(&usernamePath)
		loginFailMapSlice[k]["eventUsername"] = eventUsername
		//workstation
		eventWorkstation, _ := event.GetString(&workstationPath)
		loginFailMapSlice[k]["eventWorkstation"] = eventWorkstation
		//subjectUsername
		eventSubjectUsername, _ := event.GetString(&subjectUsernamePath)
		loginFailMapSlice[k]["eventSubjectUsername"] = eventSubjectUsername
		//subjectDomain
		eventSubjectDomain, _ := event.GetString(&subjectDomainPath)
		loginFailMapSlice[k]["eventSubjectDomain"] = eventSubjectDomain
		//进程名
		eventProcessName, _ := event.GetString(&processNamePath)
		loginFailMapSlice[k]["eventProcessName"] = eventProcessName
	}
	//处理信息
	fmt.Println("------------------------用户变动-------------------------")
	for k, event := range usersOperateSlice {

		//fmt.Println(event)
		usersOperateMapSlice[k] = make(map[string]string)
		//事件时间
		eventTime := event.TimeCreated().Format(http.TimeFormat)
		usersOperateMapSlice[k]["time"] = eventTime
		//事件id
		eventID := event.EventID()
		usersOperateMapSlice[k]["eventID"] = strconv.FormatInt(eventID, 10)
		//4720创建用户 4724重置账号密码 4732添加到组   4733从组中删除用户 4726删除用户账户
		if eventID == 4720 {
			usersOperateMapSlice[k]["typeID"] = "创建用户"
		} else if eventID == 4724 {
			usersOperateMapSlice[k]["typeID"] = "重置账号"
		} else if eventID == 4732 {
			usersOperateMapSlice[k]["typeID"] = "添加到组中"
		} else if eventID == 4733 {
			usersOperateMapSlice[k]["typeID"] = "从组中删除"
		} else if eventID == 4726 {
			usersOperateMapSlice[k]["typeID"] = "删除用户"
		}
		//ip地址
		eventIp, _ := event.GetString(&ipAddressPath)
		usersOperateMapSlice[k]["eventIp"] = eventIp
		//用户名
		eventUsername, _ := event.GetString(&usernamePath)
		usersOperateMapSlice[k]["eventUsername"] = eventUsername
		//workstation
		eventWorkstation, _ := event.GetString(&workstationPath)
		usersOperateMapSlice[k]["eventWorkstation"] = eventWorkstation
		//subjectUsername
		eventSubjectUsername, _ := event.GetString(&subjectUsernamePath)
		usersOperateMapSlice[k]["eventSubjectUsername"] = eventSubjectUsername
		//subjectDomain
		eventSubjectDomain, _ := event.GetString(&subjectDomainPath)
		usersOperateMapSlice[k]["eventSubjectDomain"] = eventSubjectDomain
		//进程名
		eventProcessName, _ := event.GetString(&processNamePath)
		usersOperateMapSlice[k]["eventProcessName"] = eventProcessName
	}
	//处理信息
	fmt.Println("------------------------删除日志-------------------------")
	for k, event := range clearHistorySlice {
		//fmt.Println(event)
		//fmt.Println(event)
		clearHistoryMapSlice[k] = make(map[string]string)
		//事件时间
		eventTime := event.TimeCreated().Format(http.TimeFormat)
		clearHistoryMapSlice[k]["time"] = eventTime
		//事件id
		eventID := event.EventID()
		clearHistoryMapSlice[k]["eventID"] = strconv.FormatInt(eventID, 10)
		//事件类型id
		typeID, _ := event.GetString(&typeIDpath)
		clearHistoryMapSlice[k]["typeID"] = typeID
		//ip地址
		eventIp, _ := event.GetString(&ipAddressPath)
		clearHistoryMapSlice[k]["eventIp"] = eventIp
		//用户名
		eventUsername, _ := event.GetString(&usernamePath)
		clearHistoryMapSlice[k]["eventUsername"] = eventUsername
		//workstation
		eventWorkstation, _ := event.GetString(&workstationPath)
		clearHistoryMapSlice[k]["eventWorkstation"] = eventWorkstation
		//subjectUsername
		eventSubjectUsername, _ := event.GetString(&subjectUsernamePath)
		clearHistoryMapSlice[k]["eventSubjectUsername"] = eventSubjectUsername
		//subjectDomain
		eventSubjectDomain, _ := event.GetString(&subjectDomainPath)
		clearHistoryMapSlice[k]["eventSubjectDomain"] = eventSubjectDomain
		//进程名
		eventProcessName, _ := event.GetString(&processNamePath)
		clearHistoryMapSlice[k]["eventProcessName"] = eventProcessName
	}

	//netstat -ano
	portInfo := GetCmdResult("netstat -ano")
	//fmt.Println(portInfo)
	tasklistInfo := GetCmdResult("tasklist")
	//fmt.Println(tasklistInfo)
	wmicInfo := GetCmdResult("wmic process get name,executablepath,processid")
	//fmt.Println(wmicInfo)
	//定时任务
	schtasksInfo := GetCmdResult("schtasks")
	//用户信息
	var userInfoResult string
	userInfocmd := GetCmdResult("net user")
	userInfoResult = userInfoResult + userInfocmd + "\n"
	RegeditUsersNamesPath := "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names"
	userinfoRegedit := GetRegeditResult(RegeditUsersNamesPath)
	if userinfoRegedit == "" {
		userInfoResult = userInfoResult + "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names 注册表未开启" + "\n"
	}
	regeditUserInfo := GetRegeditUser()
	userInfoResult = userInfoResult + "\n" + regeditUserInfo
	//获取自启动信息
	StartUpInfo := GetStartupResult()
	fmt.Println(StartUpInfo)

	return loginSuccessMapSlice, loginFailMapSlice, usersOperateMapSlice, clearHistoryMapSlice, portInfo, tasklistInfo, wmicInfo, schtasksInfo, StartUpInfo, userInfoResult

}

func GetRegeditUser() string {
	var RegeditUser string
	// 打开注册表项
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		fmt.Printf("无法打开注册表项：%v\n", err)
		return RegeditUser
	}
	defer k.Close()

	// 获取所有子项的名称
	subkeyNames, err := k.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Printf("无法获取子项名称：%v\n", err)
		return RegeditUser
	}

	// 遍历每个子项，获取 ProfileImagePath 的值
	for _, name := range subkeyNames {
		subkey, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			fmt.Printf("无法打开子项：%v\n", err)
			continue
		}
		defer subkey.Close()

		profileImagePath, _, err := subkey.GetStringValue("ProfileImagePath")
		if err != nil {
			fmt.Printf("无法获取 ProfileImagePath 值：%v\n", err)
			continue
		}
		fmt.Printf("%s -> %s\n", name, profileImagePath)
		RegeditUser = RegeditUser + name + " -> " + profileImagePath + "\n"
	}
	return RegeditUser
}

func GetCmdResult(cmdline string) string {
	cmdslice := strings.Split(cmdline, " ")
	var cmd *exec.Cmd

	if len(cmdslice) == 1 {
		cmd = exec.Command(cmdslice[0])
	} else if len(cmdslice) == 2 {
		cmd = exec.Command(cmdslice[0], cmdslice[1])
	} else if len(cmdslice) == 4 {
		cmd = exec.Command(cmdslice[0], cmdslice[1], cmdslice[2], cmdslice[3])
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err)
	}
	output, _ := simplifiedchinese.GB18030.NewDecoder().String(string(out))

	return output
}

func GetRegeditResult(cmdline string) string {
	var RegeditResult string
	key, err := registry.OpenKey(registry.CURRENT_USER, cmdline, registry.QUERY_VALUE)
	if err != nil {
		// 处理错误
	}
	defer key.Close()

	// 获取所有的值名称
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		// 处理错误
	}

	// 遍历所有的值名称，获取启动项名称和程序路径
	for _, valueName := range valueNames {
		value, _, err := key.GetStringValue(valueName)
		if err != nil {
			// 处理错误
		}

		RegeditResult = RegeditResult + valueName + value + "\n"
	}
	return RegeditResult

}

func GetStartupResult() string {

	var StartUp string
	// 获取 Windows 自启动目录
	startupDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

	// 遍历自启动目录中的文件
	StartUp = "Windows 自启动目录：" + "\n"
	filepath.Walk(startupDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			StartUp = StartUp + info.Name() + "\n"
		}
		return nil
	})

	// 获取注册表中的启动项
	StartUp = StartUp + "注册表启动项：" + "\n"
	result := GetRegeditResult("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
	StartUp = StartUp + result
	return StartUp
}
