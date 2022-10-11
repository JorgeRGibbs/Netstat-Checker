<# 
---------------- Netstat IP Checker ----------------
Name:Netstat Checker
Description: Script which snatches IP addresses from active connections and looks them up in AbuseIPDB to find any potentially malicious connections in the system.
Version: 0.1
Author: Jorge Gibbs (@V4ltzz)
#>



Write-Host '
$$\   $$\ $$$$$$$$\ $$$$$$$$\  $$$$$$\ $$$$$$$$\  $$$$$$\ $$$$$$$$\        $$$$$$\  $$\   $$\ $$$$$$$$\  $$$$$$\  $$\   $$\ $$$$$$$$\ $$$$$$$\  
$$$\  $$ |$$  _____|\__$$  __|$$  __$$\\__$$  __|$$  __$$\\__$$  __|      $$  __$$\ $$ |  $$ |$$  _____|$$  __$$\ $$ | $$  |$$  _____|$$  __$$\ 
$$$$\ $$ |$$ |         $$ |   $$ /  \__|  $$ |   $$ /  $$ |  $$ |         $$ /  \__|$$ |  $$ |$$ |      $$ /  \__|$$ |$$  / $$ |      $$ |  $$ |
$$ $$\$$ |$$$$$\       $$ |   \$$$$$$\    $$ |   $$$$$$$$ |  $$ |         $$ |      $$$$$$$$ |$$$$$\    $$ |      $$$$$  /  $$$$$\    $$$$$$$  |
$$ \$$$$ |$$  __|      $$ |    \____$$\   $$ |   $$  __$$ |  $$ |         $$ |      $$  __$$ |$$  __|   $$ |      $$  $$<   $$  __|   $$  __$$< 
$$ |\$$$ |$$ |         $$ |   $$\   $$ |  $$ |   $$ |  $$ |  $$ |         $$ |  $$\ $$ |  $$ |$$ |      $$ |  $$\ $$ |\$$\  $$ |      $$ |  $$ |
$$ | \$$ |$$$$$$$$\    $$ |   \$$$$$$  |  $$ |   $$ |  $$ |  $$ |         \$$$$$$  |$$ |  $$ |$$$$$$$$\ \$$$$$$  |$$ | \$$\ $$$$$$$$\ $$ |  $$ |
\__|  \__|\________|   \__|    \______/   \__|   \__|  \__|  \__|          \______/ \__|  \__|\________| \______/ \__|  \__|\________|\__|  \__|
'

# API KEY: Register at AbuseIPDB and get your API key at https://www.abuseipdb.com/account/api

# Assign the API Key to a variable

$APIKey = " "

# Store the output of netstat in the variable $data
$data = netstat -n

FOREACH ($line in $data)
{
    
    # Remove the whitespace at the beginning on the line
    $line = $line -replace '^\s+', ''
    
    # Split on whitespaces characteres
    $line = $line -split '\s+'
    
    # Define Properties
    $properties = @{
        Protocole = $line[0]
        LocalAddress = $line[1]
        ForeignAddress = $line[2]
        State = $line[3]
    }
    $address= $properties.ForeignAddress -split ':'
    $ip=$address[0]
    $port=$address[1]
    $url= "https://www.abuseipdb.com/check/"+$ip

    <#  Set header  #>
    $Header = @{
        'Key' = $APIKey;
    }
    
    $URICheck = "https://api.abuseipdb.com/api/v2/check"
    $BodyCheck = @{
        'ipAddress' = $ip;
        'maxAgeInDays' = '90';
        'verbose' = '';
    }
    try {

        if (($url -ne "127.0.0.1") -and ($url -ne " ") -and ($ip -match "^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$")) {
            $AbuseIPDB = Invoke-RestMethod -Method GET $URICheck -Header $Header -Body $BodyCheck -ContentType 'application/json; charset=utf-8' 
            $address = $AbuseIPDB.data.ipAddress
            $ConfidenceScore = $AbuseIPDB.data.abuseConfidenceScore
            $isPublic = $AbuseIPDB.data.isPublic
            $country = $AbuseIPDB.data.countryName
            $isWhitelisted = $AbuseIPDB.data.isWhitelisted
            $domain = $AbuseIPDB.data.domain
            $lastReport = $AbuseIPDB.data.lastReportedAt
            $Hostnames = $AbuseIPDB.data.hostnames
            $connectionStatus = $properties.State
            $Protocol = $properties.Protocole

            if ($ConfidenceScore -gt 0) {
                Write-Host '////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////'
                Write-Host 'IP:' $address
                Write-Host 'Port:' $port
                Write-Host 'Protocol:' $Protocol
                Write-Host 'Status:' $connectionStatus
                Write-Host 'Domain:' $domain
                Write-Host 'Hostnames:' $Hostnames
                Write-Host 'Confidence of abuse:' $ConfidenceScore
                Write-Host 'Country:' $country
                Write-Host 'Whitelisted:' $isWhitelisted
                Write-Host 'Last reported:' $lastReport
                Write-Host 'Public IP:' $isPublic
                Write-Host 'More information:' $url

            }    
        }
        
    } 
    Catch{
        # If error, capture status number from message
        $ErrorMessage = $_.Exception.Message
        [regex]$RegexErrorNum = "\d{3}"
        $StatusNum = ($RegexErrorNum.Matches($ErrorMessage)).Value
        Write-Host "Error:"$StatusNum
        Write-Host $ErrorMessage
    }
}
Write-Host '////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////'



