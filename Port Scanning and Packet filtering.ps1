###### TShark simple matching #######

#This creates a new alias so we dont have to define the path every time we want to  use tshark
New-Alias tshark 'C:\Program Files\Wireshark\tshark.exe'

#this writes the pcap to a different file for parsing
tshark -r "C:\users\DCI Student\Desktop\RESOURCES\Exercises\capture.pcapng" > 'C:\users\DCI Student\Desktop\beacons.txt'

#Define variables for comparison files
$IOC = Get-Content 'C:\Users\DCI Student\Desktop\Apturls.txt'
$pcap = Get-Content 'C:\Users\DCI Student\Desktop\beacons.txt'

foreach ($line in $IOC)
{
    if ($pcap | select-string -simpleMatch $line)
    {
        echo $line
    }
}

######  TCP Port Scanning ######

Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
Enable-PSRemoting -Force

#11 - 15 is the host range to scan. Write-host "x.x.x.$a" is the network and subnet declaration and ; x,x,x are the ports to scan for
1..255 | % { $a = $_; write-host "------"; write-host "10.10.10.$a"; 53,80,88,443,1434 | 
#Make sure to change the .connect ip address to match your write-host ip address
% {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.$a",$_)) "Port $_ is open!"} 2>$null}

#to do a fast and simple test for connectivity of a network use
1..255 | % { "10.10.10.$($_): $(Test-Connection -count 1 -comp 10.10.10.$($_) -quiet)" } > AllSystems.txt

####### UDP Port Scanning ########

Function Test-Subnet {
 
[cmdletbinding()]
Param(
[Parameter(Position=0,HelpMessage="Enter an IPv4 subnet ending in 0.")]
[ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
[string]$Subnet= ((Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"}).IPAddress -replace "\d{1,3}$","0"),
 
[ValidateRange(1,255)]
[int]$Start = 1,
 
[ValidateRange(1,255)]
[int]$End = 254,
 
[ValidateRange(1,10)]
[Alias("count")]
[int]$Ping = 1,
 
[int]$Port
)
 
Write-Verbose "Pinging $subnet from $start to $end"
Write-Verbose "Testing with $ping pings(s)"
 
#a hash table of parameter values to splat to Write-Progress
$progHash = @{
 Activity = "Ping Sweep"
 CurrentOperation = "None"
 Status = "Pinging IP Address"
 PercentComplete = 0
}
 
#How many addresses need to be pinged?
$count = ($end - $start)+1
 
<#
take the subnet and split it into an array then join the first
3 elements back into a string separated by a period.
This will be used to construct an IP address.
#>
 
$base = $subnet.split(".")[0..2] -join "."
 
#Initialize a counter
$i = 0
 
#loop while the value of $start is <= $end
while ($start -le $end) {
  #increment the counter
  write-Verbose $start
  $i++
  #calculate % processed for Write-Progress
  $progHash.PercentComplete = ($i/$count)*100
 
  #define the IP address to be pinged by using the current value of $start
  $IP = "$base.$start" 
 
  #Use the value in Write-Progress
  $proghash.currentoperation = $IP
  Write-Progress @proghash
 
  #get local IP
  $local = (Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"})
  
  #test the connection
  if (Test-Connection -ComputerName $IP -Count $ping -Quiet) {
    #if the IP is not local get the MAC
    if ($IP -ne $Local.IPAddress) {
        #get MAC entry from ARP table
        Try {
            $arp = (arp -a $IP | where {$_ -match $IP}).trim() -split "\s+"
            $MAC = $arp[1]
        }
        Catch {
            #this should never happen but just in case
            Write-Warning "Failed to resolve MAC for $IP"
            $MAC = "unknown"
        }
    }
    else {
        #get local MAC
        $MAC = ($local | Get-NetAdapter).MACAddress
    }
    #test Port if specified
    if ($Port) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcpconnection = $tcp.ConnectAsync($IP,$Port)
        $wait = $tcpconnection.AsyncWaitHandle.WaitOne(1000,$False)
        If ($wait) {
            #assign port number of it responds
            $PortTest = $Port
            $tcpconnection.Dispose()
        }
        else {
            Write-Verbose "Port $port not open"
            #assign Null if port not open
            $PortTest = $Null
        }
 
        $tcp.Dispose()
 
    } #if $Port
    else {
        #if not testing a port set value to Null
        $PortTest = $Null
    }
    #attempt to resolve the hostname
    Try {
        $iphost = (Resolve-DNSName -Name $IP -ErrorAction Stop).Namehost
    }
    Catch {
        Write-Verbose "Failed to resolve host name for $IP"
        #set a value
        $iphost = "unknown"
    }
    Finally {
        #create a custom object
       [pscustomobject]@{
         IPAddress = $IP
         Hostname = $iphost
         MAC = $MAC
         Port = $PortTest
       }
    }
  } #if test ping
 
  #increment the value $start by 1
  $start++
} #close while loop
 
} #end function