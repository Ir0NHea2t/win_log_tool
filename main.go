package main

import "win_log_tools/get_evtx"

func main() {
	//1，获取etvx文件数据
	loginSuccessMapSlice, loginFailMapSlice, usersOperateMapSlice, clearHistoryMapSlice, portInfo, tasklistInfo, wmicInfo, schtasksInfo, startupInfo, userInfo := get_evtx.GetEvtx()
	//2,写入文件
	get_evtx.WriteIntoFile(loginSuccessMapSlice, loginFailMapSlice, usersOperateMapSlice, clearHistoryMapSlice, portInfo, tasklistInfo, wmicInfo, schtasksInfo, startupInfo, userInfo)
}
