package get_evtx

import (
	"fmt"
	"github.com/tealeg/xlsx"
)

func WriteIntoFile(loginSuccessMapSlice []map[string]string, loginFailMapSlice []map[string]string, usersOperateMapSlice []map[string]string, clearHistoryMapSlice []map[string]string, portInfo string, tasklistInfo string, wmicInfo string, schtasksInfo string, startupInfo string, userInfo string) {
	file := xlsx.NewFile()
	loginSuccessSheet, err := file.AddSheet("登录成功")
	loginFailSheet, err := file.AddSheet("登录失败")
	usersOperateSheet, err := file.AddSheet("用户变动")
	clearHistorySheet, err := file.AddSheet("日志清理")
	portInfoSheet, err := file.AddSheet("端口信息")

	tasklistInfoSheet, err := file.AddSheet("进程信息")
	wmicInfoSheet, err := file.AddSheet("程序信息")
	schtasksInfoSheet, err := file.AddSheet("定时任务")
	startupInfoSheet, err := file.AddSheet("自启动信息")
	userInfoSheet, err := file.AddSheet("用户信息")

	if err != nil {
		fmt.Println("登录成功sheet创建失败")
	}
	writeMapSliceintoSheet(loginSuccessSheet, loginSuccessMapSlice)
	writeMapSliceintoSheet(loginFailSheet, loginFailMapSlice)
	writeMapSliceintoSheet(usersOperateSheet, usersOperateMapSlice)
	writeMapSliceintoSheet(clearHistorySheet, clearHistoryMapSlice)

	writeStringIntoSheet(portInfoSheet, portInfo)
	writeStringIntoSheet(tasklistInfoSheet, tasklistInfo)
	writeStringIntoSheet(wmicInfoSheet, wmicInfo)
	writeStringIntoSheet(schtasksInfoSheet, schtasksInfo)
	writeStringIntoSheet(startupInfoSheet, startupInfo)
	writeStringIntoSheet(userInfoSheet, userInfo)

	file.Save("./result.xlsx")
}

func writeMapSliceintoSheet(sheet *xlsx.Sheet, MapSlice []map[string]string) {
	title_row := sheet.AddRow()

	row_time := title_row.AddCell()
	row_time.Value = "时间"

	row_eventID := title_row.AddCell()
	row_eventID.Value = "eventID"

	row_typeID := title_row.AddCell()
	row_typeID.Value = "typeID"

	row_tIp := title_row.AddCell()
	row_tIp.Value = "IP"

	row_Username := title_row.AddCell()
	row_Username.Value = "Username"

	row_Workstation := title_row.AddCell()
	row_Workstation.Value = "Workstation"

	row_SubjectUsername := title_row.AddCell()
	row_SubjectUsername.Value = "SubjectUsername"

	row_SubjectDomain := title_row.AddCell()
	row_SubjectDomain.Value = "SubjectDomain"

	row_ProcessName := title_row.AddCell()
	row_ProcessName.Value = "ProcessName"

	for _, info := range MapSlice {
		//fmt.Println(info)
		row := sheet.AddRow()

		span_time := row.AddCell()
		span_time.Value = info["time"]

		span_eventID := row.AddCell()
		span_eventID.Value = info["eventID"]

		span_typeID := row.AddCell()
		span_typeID.Value = info["typeID"]

		span_Ip := row.AddCell()
		span_Ip.Value = info["eventIp"]

		span_Username := row.AddCell()
		span_Username.Value = info["eventUsername"]

		spanw_Workstation := row.AddCell()
		spanw_Workstation.Value = info["eventWorkstation"]

		span_SubjectUsername := row.AddCell()
		span_SubjectUsername.Value = info["eventSubjectUsername"]

		span_SubjectDomain := row.AddCell()
		span_SubjectDomain.Value = info["eventSubjectDomain"]

		span_ProcessName := row.AddCell()
		span_ProcessName.Value = info["eventProcessName"]
	}
}

func writeStringIntoSheet(sheet *xlsx.Sheet, info string) {

	title_row := sheet.AddRow()
	row_time := title_row.AddCell()
	row_time.VMerge = 500
	row_time.HMerge = 50
	row_time.Value = info
	row_time.SetStyle(&xlsx.Style{
		Alignment: xlsx.Alignment{
			WrapText:   true,
			Vertical:   "top",
			Horizontal: "left",
		},
	})
}
