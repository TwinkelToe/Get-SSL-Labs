# Get-SSL-Labs

Set the first two variables to the input en output csv and run.\
$DomeinCSV = Import-Csv "C:\temp\Input.csv"\
$ExportFile =  "C:\temp\Outputgit.csv"

See output.csv for example output.

Console log example:
```powershell
Looking for: rocmn.nl (1/2)
https://api.ssllabs.com/api/v3/analyze?host=rocmn.nl&all=on&fromCache=on
Status: DNS
Status: Testing renegotiation
Status: Determining available cipher suites
Status: Testing for BEAST
Status: Simulating handshakes
Status: Testing Zombie POODLE and GOLDENDOODLE
Status: READY
Result: rocmn.nl, https://www.ssllabs.com/ssltest/analyze.html?d=rocmn.nl, B, True, True,False, 83.217.76.159
Looking for: start.rocmn.nl (2/2)
https://api.ssllabs.com/api/v3/analyze?host=start.rocmn.nl&all=on&fromCache=on
Status: DNS
Status: Testing session resumption
Status: Determining available cipher suites
Status: Determining available cipher suites
Status: Testing for BEAST
Status: Testing Bleichenbacher
Status: Testing Bleichenbacher
Status: Simulating handshakes
Status: READY
Result: start.rocmn.nl, https://www.ssllabs.com/ssltest/analyze.html?d=start.rocmn.nl, B, True, True,True, 194.171.158.106```
