Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
Enable-PSRemoting -Force

#11 - 15 is the host range to scan. Write-host "x.x.x.$a" is the network and subnet declaration and ; x,x,x are the ports to scan for
1..255 | % { $a = $_; write-host "------"; write-host "10.10.10.$a"; 53,80,88,443,1434 | 
#Make sure to change the .connect ip address to match your write-host ip address
% {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.$a",$_)) "Port $_ is open!"} 2>$null}

#to do a fast and simple test for connectivity of a network use
1..255 | % { "10.10.10.$($_): $(Test-Connection -count 1 -comp 10.10.10.$($_) -quiet)" } > AllSystems.txt

#this sorts the output of all systems so only systems that are up are shown
type .\AllSystems.txt | Select-String -Pattern "True" > UpSystems.txt

#After editing the text file to only contain Ips i will use that to check for the files.
#calc.exe is used to verify the test-path is working correctly.
$cred = Get-Credential
$path = get-content("C:\Users\DCI Student\Desktop\PathIOCs.txt")
$file = get-content("C:\Users\DCI Student\Desktop\FileIOCs.txt")
$regPath = get-content("C:\Users\DCI Student\Desktop\RegPath.txt")
$Ip = get-content("C:\Users\DCI Student\Desktop\IpIOCs.txt")
$UpSystems = get-content("C:\Users\DCI Student\Desktop\UpSystems.txt")

#in order to find some of the env variables click on the windows icon on the start menu bar
# then run, then shell:$envVar.

#This starts the loop through each system identified by the $UpSystems file
foreach($system in $UpSystems) {
    
    #This will take the identified ip and run the -ScriptBlock {} on each system.
    Invoke-Command -ComputerName $system -Credential $cred -ScriptBlock {
    #Search each path recursively identified by the $file one at a time
    foreach($fileIOC in $using:file) { Get-ChildItem -Path $path -recurse -ErrorAction SilentlyContinue -Force -Include $fileIOC }
    #Check HKCU and HKLM run key paths for sub-keys based on $regPath
    foreach($RegIOC in $using:regPath) { Get-ChildItem $RegIOC }
    #Check for identified IOC ip addresses based on $Ip
    foreach($IpIOC in $using:Ip) { Get-NetTCPConnection | Select-String $IpIOC }
    #netstat -ano | Select-String $using:IP -all | select Matches can be used in place of the get-netTCPConnection | select-string
    #send all output to a file instead of the screen
    } >> IstillHatePowershell.txt
}

<# This will look for all startup location files and show the path they are located in
$autoruns = Get-CimInstance -ClassName Win32_StartupCommand |
    Select-Object -Property Command, Description, User, Location
Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock{$using:autoruns} > $text.txt #>

#Getting the DNS Cache on a system will show all name resolutions that have been ATTEMPTED
Get-DnsClientCache

######## Alternate Data Streams (ADS) ###########
#this initializes/resets 2 counter variables and then filters for all zip files and rar files.
#after a file is found it increments the corresponding counter, then the combined total is output.
$zipCount = 0
$rarCount = 0
foreach($file in (Get-ChildItem -Path 'C:\Users\DCI Student\Documents\IdentifyDataExfil_ADS' -Filter *.zip -Recurse -ErrorAction SilentlyContinue)) { $zipCount++ }
foreach($file in (Get-ChildItem -Path 'C:\Users\DCI Student\Documents\IdentifyDataExfil_ADS' -Filter *.rar -Recurse -ErrorAction SilentlyContinue)) { $rarCount++ }
$zipCount + $rarCount

#This will get all of the files with an alternate data stream and print them to a file. The selec-string makes
#the output unsuable so I had to send the data to a file and edit it there. Afterwards that file was used as a
#reference to get the hash of the files found.
Get-ChildItem .\* -recurse | Get-Item -Stream * | Select-Object FileName, Stream | Select-String -NotMatch Stream=:$DATA >> 'C:\users\dci student\desktop\ADS.txt'
foreach( $file in Get-Content('C:\Users\DCI Student\Desktop\PowershellIsBuns.txt')) { Get-FileHash -Path $file -Algorithm SHA1 |Format-List }

<# This establishes two new variables:
    1. AdsStream gets the contents of the ADS.txt file and places them into an array. In order for this to work properly
        the AdsStream file streams MUST correspond to the file path in PowershellIsBuns.txt LINE FOR LINE.
    2. arrayCounter - this variable is used to keep the file path and the ads name synched. Every iteration of the
        loop will increment the arrayCounter and will make sure that the filepath number and ADS line number are synched.
    After the variables are established I use a foreach loop to get the file paths needed and I attempted to print them out for
        debugging purposes, but when I did I got some really unexpected output that matches nothing in either file so I left
        one of them there but commented them out. After that the loop will get the content of the ADS and send it to a file. Then
        the ADS file is formatted as a hex file and saved as a copy. Lastly, the arrayCounter is incremented to keep everything in sync.
    #>
$arrayCounter = 0
$AdsStream = Get-Content('C:\users\DCI Student\Desktop\ADS.txt')
foreach($file in Get-Content('C:\Users\DCI Student\Desktop\PowershellIsBuns.txt')) { 
    #type $file
    Get-Content -Path $file -Stream $AdsStream[$arrayCounter] > "C:\Users\DCI Student\Desktop\AdsFile$arrayCounter.txt"
    Format-Hex "C:\Users\DCI Student\Desktop\AdsFile$arrayCounter.txt" > "C:\Users\DCI Student\Desktop\AdsHexFile$arrayCounter.txt"
    #type $file
    $arrayCounter++
}

#load the function and then use the following command to get the file signatures that dont match txt extension
Get-ChildItem 'C:\Users\DCI Student\Documents\IdentifyDataExfil_ADS\*.txt' -Recurse -ErrorAction SilentlyContinue | Get-FileSignature | Where {($_.HexSignature -like "504B" -or $_.HexSignature -like "5261")} | Measure-Object
#This command will get all alternate data streams as well
Get-ChildItem 'C:\Users\DCI Student\Documents\IdentifyDataExfil_ADS\*.txt' -Recurse -ErrorAction SilentlyContinue | Get-Item -Stream * | where-object -property Stream -ne ':$DATA'

#this function was created by someone else to compare the file signature to a specified file signature.
function Get-FileSignature { 
    <# .synopsis="" displays="" a="" file="" signature="" for="" specified="" file="" or="" files="" .description="" displays="" a="" file="" signature="" for="" specified="" file="" or="" files.="" determined="" by="" getting="" the="" bytes="" of="" a="" file="" and="" looking="" at="" the="" number="" of="" bytes="" to="" return="" and="" where="" in="" the="" byte="" array="" to="" start.="" .parameter="" path="" the="" path="" to="" a="" file.="" can="" be="" multiple="" files.="" .parameter="" hexfilter="" a="" filter="" that="" can="" be="" used="" to="" find="" specific="" hex="" signatures.="" allows="" "*"="" wildcard.="" .parameter="" bytelimit="" how="" many="" bytes="" of="" the="" file="" signature="" to="" return.="" default="" value="" is="" 2.="" (display="" first="" 2="" bytes)="" .parameter="" byteoffset="" where="" in="" the="" byte="" array="" to="" start="" displaying="" the="" signature.="" default="" value="" is="" 0="" (first="" byte)="" .notes="" name:="" get-filesignature="" author:="" boe="" prox="" .outputs="" system.io.fileinfo.signature="" .link="" http://en.wikipedia.org/wiki/list_of_file_signatures="" #="">
    #Requires -Version 3.0 #>
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [Alias("PSPath","FullName")]
       [string[]]$Path,
       [parameter()]
       [Alias('Filter')]
       [string]$HexFilter = "*",
       [parameter()]
       [int]$ByteLimit = 2,
       [parameter()]
       [Alias('OffSet')]
       [int]$ByteOffset = 0
    )
    Begin {
        #Determine how many bytes to return if using the $ByteOffset
        $TotalBytes = $ByteLimit + $ByteOffset

        #Clean up filter so we can perform a regex match
        #Also remove any spaces so we can make it easier to match
        [regex]$pattern = ($HexFilter -replace '\*','.*') -replace '\s',''
    }
    Process {  
        ForEach ($item in $Path) { 
            Try {                     
                $item = Get-Item -LiteralPath (Convert-Path $item) -Force -ErrorAction Stop
            } Catch {
                Write-Warning "$($item): $($_.Exception.Message)"
                Return
            }
            If (Test-Path -Path $item -Type Container) {
                Write-Warning ("Cannot find signature on directory: {0}" -f $item)
            } Else {
                Try {
                    If ($Item.length -ge $TotalBytes) {
                        #Open a FileStream to the file; this will prevent other actions against file until it closes
                        $filestream = New-Object IO.FileStream($Item, [IO.FileMode]::Open, [IO.FileAccess]::Read)

                        #Determine starting point
                        [void]$filestream.Seek($ByteOffset, [IO.SeekOrigin]::Begin)

                        #Create Byte buffer to read into and then read bytes from starting point to pre-determined stopping point
                        $bytebuffer = New-Object "Byte[]" ($filestream.Length - ($filestream.Length - $ByteLimit))
                        [void]$filestream.Read($bytebuffer, 0, $bytebuffer.Length)

                        #Create string builder objects for hex and ascii display
                        $hexstringBuilder = New-Object Text.StringBuilder
                        $stringBuilder = New-Object Text.StringBuilder

                        #Begin converting bytes
                        For ($i=0;$i -lt $ByteLimit;$i++) {
                            If ($i%2) {
                                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                            } Else {
                                If ($i -eq 0) {
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                } Else {
                                    [void]$hexstringBuilder.Append(" ")
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                }        
                            }
                            If ([char]::IsLetterOrDigit($bytebuffer[$i])) {
                                [void]$stringBuilder.Append([char]$bytebuffer[$i])
                            } Else {
                                [void]$stringBuilder.Append(".")
                            }
                        }
                        If (($hexstringBuilder.ToString() -replace '\s','') -match $pattern) {
                            $object = [pscustomobject]@{
                                Name = ($item -replace '.*\\(.*)','$1')
                                FullName = $item
                                HexSignature = $hexstringBuilder.ToString()
                                ASCIISignature = $stringBuilder.ToString()
                                Length = $item.length
                                Extension = $Item.fullname -replace '.*\.(.*)','$1'
                            }
                            $object.pstypenames.insert(0,'System.IO.FileInfo.Signature')
                            Write-Output $object
                        }
                    } ElseIf ($Item.length -eq 0) {
                        Write-Warning ("{0} has no data ({1} bytes)!" -f $item.name,$item.length)
                    } Else {
                        Write-Warning ("{0} size ({1}) is smaller than required total bytes ({2})" -f $item.name,$item.length,$TotalBytes)
                    }
                } Catch {
                    Write-Warning ("{0}: {1}" -f $item,$_.Exception.Message)
                }

                #Close the file stream so the file is no longer locked by the process
                $FileStream.Close()
            }
        }        
    }
}

#this was part of the steganography challenge
Format-Hex 'C:\Users\DCI Student\Desktop\Lady_Liberty.jpg' > ladylibhex.txt