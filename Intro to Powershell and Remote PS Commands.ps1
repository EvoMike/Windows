get-alias
Set-ExecutionPolicy Unrestricted

#One line comment

<#
Multi
Line
comment
#>

#make a directory
mkdir E:\Powershell_content

#Create a new document
New-Item -Path E:\Powershell_content -Name a.txt -Value "Important content to remember"

#Get the content of a file
Get-Content E:\Powershell_content\a.txt

mkdir E:\Powershell_content\dirA
mkdir E:\Powershell_content\dirB

#Create items in dirA and copy them to dirB
New-Item -Path E:\Powershell_content\dirA\5.txt
Copy-Item E:\Powershell_content\dirA\* E:\Powershell_content\dirB

<# 5 basic commands to remember
Get-Content
Set-Content
Add-Content
New-Item
Remove-Item #>

#creating a for loop to copy files 1-4 using the $files array
$i = 1..4
$files = Get-ChildItem -Path E:\Powershell_content\dirA\
foreach($file in $files[0..3]){
Copy-Item -Path E:\Powershell_content\dirA\$file -Destination E:\Powershell_content\dirb\
}

#Sorting and selecting object types
Get-ChildItem E:\Powershell_content\dirA\ | Sort-Object LastWriteTime -Descending
Get-Service | Where-Object -Property Status -EQ Running 
Get-Service | Sort-Object Name

#Sending output to a csv file
Get-Process | Select-Object ProcessName,ID | Export-Csv E:\Powershell_content\Processes.csv -NoTypeInformation

#using MD5 hashing
Get-FileHash -Algorithm MD5 -Path E:\Steganography\Theme2\*
#or
Get-ChildItem E:\Steganography\Theme2 | Get-FileHash -Algorithm MD5 | Export-Csv E:\Steganography\Hashes.csv -NoTypeInformation

#Network statistics
Get-NetTCPConnection
Get-NetUDPEndpoint

#LOGIC AND LOOPING
$x = 50
if($x -gt 10){
    echo "$x > 10"
}
elseif($x -lt 10){
    echo "$x < 10"
}
else{
    echo "$x = 10"
}

#Error handling
#find calc.exe in the C drive and dont display errors
Get-ChildItem C:\ -Include calc.exe -Recurse -Force -ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5
Get-FileHash -Algorithm MD5 E:\Malware\calc.exe

<#Volitility.exe commands:
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" imageinfo > E:\Dest\file\path
    ^This command MUST be used first to get the profiles you could use
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile pslist(tree) > file\path
    ^This command will get a process list or a process tree from the mem dump
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile procdump -p pid -D \dest\dir
    ^will grab a process from memory according to its pid and place it in \dest\dir
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile handles -p 1628 -t mutant > file\path
    ^will show handles for process pid 1628 and gives mutants for that pid
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile getsids -p 1628 > file\path
    ^will get the sids pertaining to pid 1628
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile netscan > file\path
    ^will get all connection info that was in memory
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile psxview > file\path
    ^this command will show hidden processes
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile cmdscan > file\path
    ^will get the last commands used in the command line
volitility.exe -f "E:\Memory Forensics\MemoryDumpFile" --profile=profile dlllist > file\path
    ^shows a list of dlls that a process starts

In order to verify whether or not a process is malicious you can get the hash of the process after it has been dumped
and use it to check against virus total or some other hash database.
#>

#Search the entire C:\ drive for the hosts file, search in all folders including hidden, and 
#don't show error messages.
Get-ChildItem -Path C:\ -Include "hosts" -Recurse -Force -ErrorAction SilentlyContinue

#Search for any subkeys in the typical regestries of persistance.
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Get-ChildItem HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

#Search for any .exes in the typical regestries of persistance themselves.
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

#Search for .exes that are IOCs for APT28 after running the winsystra.exe CTE program and print results to CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "vmwaremanager.exe" -Recurse -Force -ErrorAction SilentlyContinue > CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "hazard.exe" -Recurse -Force -ErrorAction SilentlyContinue >> CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "wintraysys.exe" -Recurse -Force -ErrorAction SilentlyContinue >> CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "hpinst.exe" -Recurse -Force -ErrorAction SilentlyContinue >> CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "csrs.exe" -Recurse -Force -ErrorAction SilentlyContinue >> CTEexeIocs.txt
Get-ChildItem -Path C:\ -Include "runrun.exe" -Recurse -Force -ErrorAction SilentlyContinue >> CTEexeIocs.txt
#ensure that the results were printed to the file
type CTEexeIocs.txt

#I will use pslist from the pstools toolkit to find how many threads the winsystray process is using.
& 'C:\Users\DCI Student\Desktop\PSTools\pslist.exe'

#I will use the handle.exe tool from sysinternals tools to find the mutant from the winsystray program that was
#started by the CTE malware.
& 'C:\Users\DCI Student\Desktop\SysinternalsSuite\handle.exe' -a -p 5392 | findstr "Mutant"

#These are the commands I ran to enable myself to do a remote pssession.
#The cred username is 'DCI Student' and the password is P@ssw0rd.
Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
Enable-PSRemoting -Force
$cred = Get-Credential
New-PSSession -ComputerName 10.10.10.14 -Credential $cred
Enter-PSSession -Id 1

#These are the steps I took after getting on the machine
dir
Get-Process > processlist.txt
dir
netstat > netstat.txt
type .\processlist.txt
type .\netstat.txt
Stop-Process -Name cmd

Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*
#Get-ItemProperty will show the actual subkey names within the run key
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*
#Get-ChildItem HKCU:\*\Software\Microsoft\Windows\currentversion\run\*
#TCP    10.10.10.14:63185      a96-17-4-65:https      SYN_SENT

dir C:\ > Cdir.txt
type C:\start.bat
type C:\nogui.ps1

#to attempt to resolve the issue I'm going to rename start.bat (to preserve evidence) so the run key
#doesn't know to run that file. Then I will restart and relog into the machine.
move-item C:\start.bat C:\dontstart.bat
dir C:\
Stop-Process -Name powershell -Force
Get-Process Explorer | %
Restart-Computer -Force
Get-Process

#the process list looks normal! since the run key didnt reference the new name for the batch file it
#no longer starts it. Now to do the exercise
#Enumerate users
Get-LocalUser
#get logical disks and disk space
Get-WmiObject -Class Win32_LogicalDisk
#list out event logs
Get-EventLog -List
#list system logs concerning the task scheduler and send it to appeventlog100.txt
#tried this as well but its not useful for this exerciseGet-EventLog -LogName EC2ConfigService -Newest 100 > EC2eventlog100.txt
Get-EventLog -LogName System -Newest 100 -Source Microsoft-Windows-TaskScheduler > Appeventlog100.txt
#this is an alternate way to do the same thing as the command above
Get-EventLog -LogName System | where Message -like "misconfig*"
type .\Appeventlog100.txt
#this is how you would see what the nogui task is doing
(Get-ScheduledTask -TaskName nogui).Actions
#this is another way to find it
Get-ScheduledTask | select TaskName -ExpandProperty actions | select taskname, execute | findstr ".bat"

#Inovke-Command runs commands remotely and returns results
#$csv = Export-Csv C:\Info.csv -NoTypeInformation
Invoke-Command -ComputerName 10.10.10.104 -Credential $cred -ScriptBlock{Get-Process >> C:\info.txt; Get-Service | Where-Object -Property status -EQ Running >> C:\info.txt; Get-NetTCPConnection -State Established >> C:\info.txt}

$session = New-PSSession -ComputerName 10.10.10.104 -Credential $cred
#copy info.txt from remote session
Copy-Item -FromSession $session -Path C:\info.txt -Destination E:\info.txt