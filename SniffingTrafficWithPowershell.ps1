#Here is a script to sniff traffic coming from and destined to an individual machine without having to install anything
# on the machines. (will have to install windows message analyzer on the local machine to parse the .etl file to a .cap
# file to input into wireshark):

#The first part just assigns the variables that will be used. It will also set the host IP variable list that will be
# iterated through.
$cred = Get-Credential
$hostIPs = Get-Content C:\Users\$username\Documents\HostIPs.txt


#This loop sets up the iteration to sniff the traffic on each individual machine.
foreach ( $IP in $hostIPs ) {

    #This is just setting a variable for the name of the files. I put this inside the loop because each file will have
    # to be created on the host machine and then it will have to get transferred to your local machine. I put this
    # inside of the for loop so the file name will describe which host it is coming from. Also, the .etl extension is
    # a windows file format that is readable by Windows Message Analyzer, which can then be converted to a pcap file.
    $traceFileName = "$IP"+"_"+(Get-Date -Format "yyyyMMdd_HHmm")+".etl"
    Invoke-Command -ComputerName $IP -Credential $cred -ScriptBlock {

        #This script block starts the netsh trace command, which does the traffic sniffing and then goes to sleep
        # for 60 seconds so traffic can be captured. The last command then stops the trace and saves the file.
        netsh trace start scenario=NetConnection session='TraceTest' capture=yes tracefile=C:\$using:traceFileName
        sleep 60
        netsh trace stop session='TraceTest'
    }

    #The last two lines are used to remotely copy the file that was just made on the host machine to your local machine.
    # I would place these in their own folder. After the file is copied you can use Windows Message Analyzer to convert
    # this file to a .cap file so you can use wireshark to view the data.
    $session = New-PSSession -ComputerName $IP -Credential $cred
    Copy-Item "C:\$traceFileName" -Destination C:\Users\$username\Documents\DNSEnum\$traceFileName -FromSession $session
}