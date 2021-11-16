function Get-Processes {
	return Get-Process -IncludeUserName | Format-List Username, Name, ID
}
