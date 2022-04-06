function InvaderBlock{
    <#
    .SYNOPSIS
        Blocks Invaders in Elden Ring using Windows Firewall Rules. Run this script after you have already summoned your allies
        Requires admin and custom scripts to be allowed. Run at your own risk
    .DESCRIPTION
        Creates a Windows Firewall rule to block all UDP traffic originating from steam.exe that are not IP Addresses listed in an adjacent file Whitelist.txt
        Most of the logic here is due to Windows Firewall not being able to prioritize / cascade on firewall rules and automatically prioritizing "deny" rules
        Due to this, we have to define a blacklist of IPs addresses (all IPv4 addresses in existence, minus your whitelist)

        Order of use:
            1. Go online in Elden Ring
            2. Summon your friend
            3. Once your friend is fully summoned, run this script
            4. If you or your summon dies, run "InvaderBlock-stop.ps1" and return to step 1

        You can also pass the string "stop" under the -mode parameter to reverse the firewall rule
    .INPUTS
        System.String
    #>
    param (
            [Parameter (Mandatory = $false)] [String]$mode
    )

    function ConvertTo-DottedDecimalIP {
        <#
        .SYNOPSIS
            Converts either an unsigned 32-bit integer or a dotted binary string to an IP Address.
        .DESCRIPTION
             ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
        .INPUTS
            System.String
        .EXAMPLE
            ConvertTo-DottedDecimalIP 11000000.10101000.00000000.00000001
            Convert the binary form back to dotted decimal, resulting in 192.168.0.1.
        .EXAMPLE
            ConvertTo-DottedDecimalIP 3232235521
            Convert the decimal form back to dotted decimal, resulting in 192.168.0.1.
        #>

        [CmdletBinding()]
        [OutputType([IPAddress])]
        param (
            # A string representation of an IP address from either UInt32 or dotted binary.
            [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
            [String]$IPAddress
        )

        process {
            try {
                [Int64]$value = 0
                if ([Int64]::TryParse($IPAddress, [Ref]$value)) {
                    return [IPAddress]([IPAddress]::NetworkToHostOrder([Int64]$value) -shr 32 -band [UInt32]::MaxValue)
                } else {
                    [IPAddress][UInt64][Convert]::ToUInt32($IPAddress.Replace('.', ''), 2)
                }
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [ArgumentException]'Cannot convert this format.',
                    'UnrecognisedFormat',
                    'InvalidArgument',
                    $IPAddress
                )
                Write-Error -ErrorRecord $errorRecord
            }
        }
    }

    function ConvertTo-DecimalIP {
        <#
        .SYNOPSIS
            Converts a Decimal IP address into a 32-bit unsigned integer.
        .DESCRIPTION
            ConvertTo-DecimalIP takes a decimal IP, uses a shift operation on each octet and returns a single UInt32 value.
        .INPUTS
            System.Net.IPAddress
        .EXAMPLE
            ConvertTo-DecimalIP 1.2.3.4
            Converts an IP address to an unsigned 32-bit integer value.
        #>

        [CmdletBinding()]
        [OutputType([UInt32])]
        param (
            # An IP Address to convert.
            [Parameter(Mandatory, Position = 1, ValueFromPipeline )]
            [IPAddress]$IPAddress
        )

        process {
            [UInt32]([IPAddress]::HostToNetworkOrder($IPAddress.Address) -shr 32 -band [UInt32]::MaxValue)
        }
    }

    function IPblacklist($whiteListIPs){
        <#
        .SYNOPSIS
            Converts either an unsigned 32-bit integer or a dotted binary string to an IP Address.
        .DESCRIPTION
             ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
        .INPUTS
            System.String
        .EXAMPLE
            ConvertTo-DottedDecimalIP 11000000.10101000.00000000.00000001
            Convert the binary form back to dotted decimal, resulting in 192.168.0.1.
        .EXAMPLE
            ConvertTo-DottedDecimalIP 3232235521
            Convert the decimal form back to dotted decimal, resulting in 192.168.0.1.
        #>
        $lowerbound = 0
        $upperbound = 4294967295

        $whitelistDec = @()
        foreach ($IP in $whiteListIPs){
            $whitelistDec += ConvertTo-DecimalIP($IP)
        }

        $blacklistDec = @()

        for ($i = 0; $i -lt $whitelistDec.Length; $i++) {
            if($i -eq 0){
                $blacklistDec += $lowerbound
            }
    
            $blacklistDec += ($whitelistDec[$i] - 1)
            $blacklistDec += ($whitelistDec[$i] + 1)

            if($i -eq ($whitelistDec.Length - 1)){
                $blacklistDec += $upperbound
            } else {
                
            }
        }

        $blackListIP = @()
        $ipRange = ""
        for ($i = 0; $i -lt $blacklistDec.Length; $i++) {
            $ipRange += (ConvertTo-DottedDecimalIP($blacklistDec[$i])).IPAddressToString
            if($i -eq ($blacklistDec.Length)){
                 break
            }
            elseif($i % 2 -eq 0 ){
                $ipRange += "-"
            }
            elseif($i % 2 -eq 1 ){
                $blackListIP += $ipRange
                $ipRange = ""
            }
        }

        return $blackListIP
    }

    # Fetch the IP Addresses, seperated by newline, from Whitelist.txt
    Try{
        $textFile = Get-Content Whitelist.txt -ErrorAction Stop
    } catch {
        Write-Output "Please create a file called 'Whitelist.txt' adjacent to the script. One IP address per line"
        Exit
    }

    # Convert the whitelist into a blacklist (Windows Firewall does not work well with whitelists)
    $blacklist = IPblacklist($textFile)
    $ruleName = "Elden Ring Blocker"
    $steamPath = "%ProgramFiles% (x86)\Steam\steam.exe"

    # Remove prior rules as to not make duplicates
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    if($mode -ne "stop"){
        try{
            New-NetFirewallRule -DisplayName $ruleName -Program $steamPath -Direction Outbound -Protocol UDP -RemoteAddress $blacklist -Action Block
        } catch [Exception]{
            #TO DO - Fix Error Handling
            Write-Output "Error creating firewall rule. Are you running the script as admin?"
        }
    } else {
        Write-Output "Elden Ring Firewall Rule Removed"
    }
}

InvaderBlock -mode "Stop"
