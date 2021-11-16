function Get-Processes {
	return Get-Process -Name * -IncludeUserName
}
