$DomeinCSV = Import-Csv "C:\temp\Input.csv"
$ExportFile =  "C:\temp\Outputgit.csv"

$SSLLabsUseCache = $true #Mogen resultaten uit de cache komen?
<# 
API documentatie: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
/analyze?host=www.ssllabs.com
https://api.ssllabs.com/api/v3/analyze?host=www.rocmn.nl
#>

$APIendpoint = "https://api.ssllabs.com/api/v3/analyze?host="
$UniekeDomeinen = $DomeinCSV.Domains | Sort-Object | Get-Unique
$TotalToCheck = $UniekeDomeinen.Count
$LijstMetDomeinen = @()

class DomeinObj {
    [string]$MatchingIdentities
    [string]$LinkSSLLabs
    [string]$Classificering
    [string]$TLS10
    [string]$TLS11
    [string]$RC4
    [string]$IP

    DomeinObj($MatchingIdentities, $LinkSSLLabs, $Classificering, $TLS10, $TLS11, $RC4, $IP) {
        $this.MatchingIdentities = $MatchingIdentities
        $this.LinkSSLLabs = $LinkSSLLabs
        $this.Classificering = $Classificering
        $this.TLS10 = $TLS10
        $this.TLS11 = $TLS11
        $this.RC4 = $RC4
        $this.IP = $IP
    }
}
$i = 0
$UniekeDomeinen | ForEach-Object {
    $i++
    $Result = ""
    $tempLink = ""
    $tempName = ""

    "Looking for: " + $_ + " ($i/$TotalToCheck)"

    #temp vars.. van try overschrijft $_
    $tempLink = "https://www.ssllabs.com/ssltest/analyze.html?d="+$($_)
    $tempName = $_

    # Is het een wildcard cert?
    if ($_.contains('*')) {
        "Status: Wildcard in name. Skipping."
        $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink,'Wildcard', 'n/a', 'n/a', 'n/a', 'n/a')
        return
    }

    #craft uri
    $uri = $APIendpoint + $_ + '&all=on'
    if ($SSLLabsUseCache) { $uri + "&fromCache=on" }
    
    #Inital lookup en wacht op op status READY of ERROR
    $Result = Invoke-RestMethod -Uri $uri
    "Status: " + $Result.status 
    while (($Result.status -eq "IN_PROGRESS") -or ($Result.status -eq "DNS" )){
        Start-Sleep -Seconds 20
        $Result = Invoke-RestMethod -Uri $uri
        if ($Result.endpoints.statusDetailsMessage) {
            "Status: " + $Result.endpoints.statusDetailsMessage            
        } else {
            "Status: " + $Result.status
        }
        if ($Result.status -eq "READY"){
            break
        }
    }

    #Status ready.
    if ($Result.status -eq "READY") {
        
        #Unable to connect to server is geen error blijkbaar...
        if ($Result.endpoints.statusMessage -eq "Unable to connect to the server") {
            "Status: Unable to connect to server."
            $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink, $Result.endpoints.statusMessage, 'n/a', 'n/a', 'n/a', $($Result.endpoints.ipAddress))
        } else {
            # Resultaat wegschrijven
            try {
                # Try omdat sommige velden niet altijd bestaan.
                $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink, `
                    $($Result.endpoints.grade), $($Result.endpoints.details.protocols.version.Contains('1.0')), `
                    $($Result.endpoints.details.protocols.version.Contains('1.1')), `
                    $($Result.endpoints.details.supportsRc4), $($Result.endpoints.ipAddress))
        
                "Result: $tempName, $tempLink, $($Result.endpoints.grade), $($Result.endpoints.details.protocols.version.Contains('1.0')), $($Result.endpoints.details.protocols.version.Contains('1.1')),$($Result.endpoints.details.supportsRc4), $($Result.endpoints.ipAddress)"
            } catch {
                 $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink, $($Result.endpoints.statusMessage), 'n/a', 'n/a', 'n/a', $($Result.endpoints.ipAddress))
                  "Result: $tempName, $tempLink, $($Result.endpoints.statusMessage), $($Result.endpoints.ipAddress)"
            }
        }
    # ERROR status retour van SSLlabs
    } elseif ($Result.status -eq "ERROR") {
        "Status error domein: $($_). SKIPPING"
        $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink, $($Result.statusMessage), 'n/a', 'n/a', 'n/a', 'n/a')
        "Result: $tempName, https://www.ssllabs.com/ssltest/analyze.html?d=$($tempName), $($Result.statusMessage), $($Result.endpoints.ipAddress)"
    # Geen resultaat maar ook geen Error van SSL laps (Cheapo Catch all)
    } else {
        "Onverwachte status domein: $($_)."
        $LijstMetDomeinen += New-Object DomeinObj($tempName, $tempLink,'Script Error/SSLLabs overloaded', 'n/a', 'n/a', 'n/a', 'n/a')
        "Result: $tempName, https://www.ssllabs.com/ssltest/analyze.html?d=$($tempName), $($Result.statusMessage), $($Result.endpoints.ipAddress)"
    }
}

$LijstMetDomeinen | Export-Csv -Path $ExportFile
$LijstMetDomeinen | Out-GridView