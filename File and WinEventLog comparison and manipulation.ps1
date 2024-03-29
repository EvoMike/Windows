#use regex to create a csv file from the txt file
#this will set the object names for the columns
echo "SHA256,Path" > FileContents.txt
#this iterates through all lines and replaces the line breaks with commas on every line with C:
(Get-Content .\System32baseline.txt -Raw).Replace("`r`nC:",",C:") >> FileContents.txt

Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted
Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
Enable-PSRemoting -Force
$cred = Get-Credential
New-PSSession -ComputerName 172.16.12.20 -Credential $cred
Enter-PSSession -Id 3
Get-ChildItem -Path C:\ -Recurse -Force | Get-FileHash -Algorithm SHA256 | Export-Csv Machine2FileHash.csv
Exit-PSSession
$session = New-PSSession -ComputerName 172.16.12.20 -Credential $cred
Copy-Item -Path C:\users\Administrator\Documents\Machine2FileHash.csv -Destination 'C:\users\DCI Student\Desktop' -FromSession $session
Import-Csv .\Machine2FileHash.csv | Select-String "chr0me.exe"
Import-Csv .\Machine2FileHash.csv | Select-String "FileHunter-Win32.exe"
Import-Csv .\Machine2FileHash.csv | Select-String "xxx.exe"
Import-Csv .\Machine2FileHash.csv | Select-String "extension.exe" 
Import-Csv .\FileContents.txt

####### Comparing files ########
$file1 = import-csv E:\Baseline-sys32.csv
$file2 = import-csv E:\Baseline-sys32.csv

#Basic compare-object
Compare-Object $file1 $file2 -Property SHA1 -PassThru | select -Property SHA1,SideIndicator,FileNames

#More advanced compare object that gets 600 values instead of 15000
Compare-Object $file1 $file2 -Property SHA1 -PassThru | Where-Object {$_.SideIndicator -eq '=>'} | 
Select -Property SHA1,FileNames | 
Export-csv E:\new-or-modified.csv -NoTypeInformation

#Compare objects from volitility output to compare PIDS. Make sure all property fields match
$baseline = Import-csv E:\baseline_pslist.csv -delimiter "|" | Select -Property Name,Id
$live = Import-Csv E:\live_pslist.csv | Select -Property Name,Id
Compare-Object $baseline $live -property Name -PassThru

######### Searching files by Creation time ##########

#Establishing variables for the file search
$process = KeyX
$FileLoc = $Process | %{Get-Process -Name $_ -FileVersionInfo}
$Creation = (Get-Item $FileLoc.FileName).CreationTimeUtc

#Get any file created + or - 1 min from identified artifact
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object{$_.CreationTimeUtc -ge $Creation.AddMinutes(-1) -and $_.CreationTimeUtc -le $Creation.AddMinutes(1)} |
        select -Property CreationTimeUtc,FullName
        
#Collect autorun information
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command,Description,User,Location |
    Out-GridView
    
######## WinEventLog Filtering and Manipulation #########


<#Looking at system logs with powershell
Gets the windows security event logs and filters for ID 4624, enclosing the entire
command in {}.count will count how many times an instance of something occurs.
or you can set the command to a variable and use $var.count#>
Get-WinEvent -LogName Security | where-object -property ID -eq 4624

#shows the last 100 events from the security logs
Get-WinEvent -LogName security -MaxEvents 100

#shows the oldest event
Get-WinEvent -LogName security -MaxEvents 1 -Oldest

# 4732 is the event log to check for users added to security enabled groups

#use get-member to find all properties an object has
Get-WinEvent -Path $eventlog |?{$_.Id -match 4624} | Measure-Object

#oldest failed logon attempt
Get-WinEvent -Path $eventlog |?{$_.Id -match 4625} | Sort-Object timecreated -Descending | Select-Object -Last 1

#what type of logon attempt was this event?
Get-WinEvent -Path $eventlog |?{$_.Id -match 4625} | Sort-Object timecreated -Descending | Select-Object -Last 1 -ExpandProperty message |findstr "Logon Type"

#Event ID for changed credentials
Get-WinEvent -Path $eventlog |?{$_.Id -match 4738} | Sort-Object timecreated -Descending | Select-Object -ExpandProperty message

#Event ID for user added to local group
Get-WinEvent -Path $eventlog |?{$_.Id -match 4732} | Sort-Object timecreated -Descending | Select-Object -Last 1 -ExpandProperty message

#Find the event that does not relate to accounts
Get-WinEvent -Path $eventlog | Sort-Object Id -Descending

#Expand the message to determine what might be "corrupt"
Get-WinEvent -Path $eventlog |?{$_.Id -match 6281} | Sort-Object timecreated -Descending | Select-Object -Last 1 -ExpandProperty message