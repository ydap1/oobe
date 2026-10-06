<#
.SYNOPSIS
    Tests whether a network allows everything Windows OOBE / Autopilot / Entra join / Intune enrolment needs.

.DESCRIPTION
    Built to diagnose "Sorry, you've lost connection" in OOBE on filtered (school) Wi-Fi.

    For every endpoint it checks:
      - DNS      : resolves, not sinkholed (0.0.0.0 / 127.x), not pointing at a private block-page IP.
                   On failure it re-tries against public DNS (1.1.1.1) to show whether the local DNS filter is the cause.
      - TCP      : port 80/443 reachable (firewall drop / reset).
      - TLS      : handshake completes (SNI filtering), certificate is genuine (detects SSL/TLS inspection).
                   A brand-new device in OOBE does NOT trust the filter's inspection CA, and many of these
                   services are certificate-pinned, so inspection = failure even on devices that trust the CA.
      - HTTP     : gets a real response, not a redirect to a captive portal / block page.
      - NCSI     : connecttest.txt returns exactly "Microsoft Connect Test" and dns.msftncsi.com resolves correctly.
                   If NCSI fails, Windows thinks there is no internet and OOBE shows "lost connection".
      - NTP      : UDP 123 to time.windows.com, and local clock offset.

    All tests use direct sockets (no proxy), which is what a device in OOBE does.

    TIP: run it once on the hotspot to create a baseline, then on the school Wi-Fi with -BaselineCsv.
         Anything that passes on the hotspot but fails on the school Wi-Fi is what the filter is blocking.

.PARAMETER OutputPath
    Folder for the CSV report and the whitelist file. Defaults to the script folder (e.g. the USB stick), or %TEMP%.

.PARAMETER BaselineCsv
    CSV produced by a previous run on a known-good network (hotspot). Results are compared against it.

.PARAMETER ShowAll
    List every endpoint on screen. By default only problems are listed, with a pass count per category.

.PARAMETER TimeoutMs
    Per-step timeout in milliseconds. Default 5000.

.PARAMETER Throttle
    Number of endpoints tested in parallel. Default 16.

.EXAMPLE
    # From OOBE: press Shift+F10, then
    powershell -ExecutionPolicy Bypass -File D:\Test-OOBEConnectivity.ps1

.EXAMPLE
    # Baseline on hotspot, then compare on school Wi-Fi
    .\Test-OOBEConnectivity.ps1                        # on hotspot  -> OOBE-Connectivity_<PC>_<SSID>_<time>.csv
    .\Test-OOBEConnectivity.ps1 -BaselineCsv .\OOBE-Connectivity_PC01_Hotspot_20261006-1200.csv
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$BaselineCsv,
    [int]$TimeoutMs = 5000,
    [int]$Throttle = 16,
    [switch]$ShowAll
)

# OOBE's console keeps little scrollback - enlarge it so nothing scrolls away
try {
    $raw = $Host.UI.RawUI
    $bs = $raw.BufferSize
    if ($bs.Height -lt 3000) { $bs.Height = 3000; $raw.BufferSize = $bs }
} catch { }

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'Continue'

#region Endpoint list
# Level|Category|URL|ExpectedBody
#   Critical    = OOBE / sign-in cannot complete without it
#   Required    = Autopilot / Entra join / Intune enrolment / activation will fail or stall
#   Recommended = Needed shortly after (apps, updates, telemetry, branding) - failures here are warnings
$EndpointDefs = @(
    # --- Network Connectivity Status Indicator: decides whether Windows thinks it is online ---
    'Critical|NCSI (connectivity check)|http://www.msftconnecttest.com/connecttest.txt|Microsoft Connect Test'
    'Recommended|NCSI (connectivity check)|http://www.msftncsi.com/ncsi.txt|Microsoft NCSI'

    # --- Certificates: a fresh device downloads root/CRL updates over plain HTTP ---
    'Critical|Certificates / CRL / OCSP|http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab|'
    'Required|Certificates / CRL / OCSP|http://crl.microsoft.com/pki/crl/products/MicRooCerAut2011_2011_03_22.crl|'
    'Required|Certificates / CRL / OCSP|http://www.microsoft.com/pkiops/crl/MicSecSerCA2011_2011-10-18.crl|'
    'Required|Certificates / CRL / OCSP|http://mscrl.microsoft.com/|'
    'Required|Certificates / CRL / OCSP|http://oneocsp.microsoft.com/|'
    'Required|Certificates / CRL / OCSP|http://ocsp.digicert.com/|'
    'Required|Certificates / CRL / OCSP|http://crl3.digicert.com/DigiCertGlobalRootG2.crl|'
    'Recommended|Certificates / CRL / OCSP|http://crl4.digicert.com/|'

    # --- OOBE web experience / Microsoft account ---
    'Critical|OOBE / Microsoft account|https://login.live.com/|'
    'Critical|OOBE / Microsoft account|https://account.live.com/|'
    'Recommended|OOBE / Microsoft account|https://signup.live.com/|'
    'Critical|OOBE / Microsoft account|https://logincdn.msauth.net/|'
    'Recommended|OOBE / Microsoft account|https://acctcdn.msauth.net/|'
    'Critical|OOBE / Microsoft account|https://go.microsoft.com/fwlink/|'
    'Recommended|OOBE / Microsoft account|https://www.microsoft.com/|'
    'Recommended|OOBE / Microsoft account|https://fs.microsoft.com/|'
    'Recommended|OOBE / Microsoft account|https://settings-win.data.microsoft.com/|'
    'Recommended|OOBE / Microsoft account|https://v10.events.data.microsoft.com/|'

    # --- Entra ID sign-in and device join ---
    'Critical|Entra ID sign-in / join|https://login.microsoftonline.com/|'
    'Critical|Entra ID sign-in / join|https://login.microsoft.com/|'
    'Critical|Entra ID sign-in / join|https://login.windows.net/|'
    'Critical|Entra ID sign-in / join|https://aadcdn.msauth.net/|'
    'Critical|Entra ID sign-in / join|https://aadcdn.msftauth.net/|'
    'Recommended|Entra ID sign-in / join|https://aadcdn.msftauthimages.net/|'
    'Critical|Entra ID sign-in / join|https://device.login.microsoftonline.com/|'
    'Critical|Entra ID sign-in / join|https://enterpriseregistration.windows.net/|'
    'Required|Entra ID sign-in / join|https://graph.microsoft.com/|'
    'Required|Entra ID sign-in / join|https://graph.windows.net/|'
    'Recommended|Entra ID sign-in / join|https://autologon.microsoftazuread-sso.com/|'
    'Recommended|Entra ID sign-in / join|https://secure.aadcdn.microsoftonline-p.com/|'
    'Recommended|Entra ID sign-in / join|https://clientconfig.microsoftonline-p.net/|'
    'Recommended|Entra ID sign-in / join|https://account.activedirectory.windowsazure.com/|'
    'Recommended|Entra ID sign-in / join|https://mysignins.microsoft.com/|'
    'Recommended|Entra ID sign-in / join|https://passwordreset.microsoftonline.com/|'

    # --- Windows Autopilot ---
    'Critical|Windows Autopilot|https://ztd.dds.microsoft.com/|'
    'Critical|Windows Autopilot|https://cs.dds.microsoft.com/|'
    'Recommended|Windows Autopilot|https://lgmsapeweu.blob.core.windows.net/|'

    # --- TPM attestation (Autopilot self-deploying / pre-provisioning) ---
    'Required|TPM attestation|https://ekop.intel.com/ekcertservice|'
    'Required|TPM attestation|https://ekcert.spserv.microsoft.com/EKCertificate/GetEKCertificate/v1|'
    'Required|TPM attestation|https://ftpm.amd.com/pki/aia|'

    # --- Intune enrolment and management ---
    'Required|Intune|https://enrollment.manage.microsoft.com/|'
    'Required|Intune|https://enterpriseenrollment.manage.microsoft.com/|'
    'Required|Intune|https://enterpriseenrollment-s.manage.microsoft.com/|'
    'Required|Intune|https://portal.manage.microsoft.com/|'
    'Required|Intune|https://m.manage.microsoft.com/|'
    'Required|Intune|https://manage.microsoft.com/|'
    'Required|Intune|https://client.wns.windows.com/|'
    'Recommended|Intune|https://swda01-mscdn.manage.microsoft.com/|'
    'Recommended|Intune|https://swdb01-mscdn.manage.microsoft.com/|'
    'Recommended|Intune|https://swdc01-mscdn.manage.microsoft.com/|'
    'Recommended|Intune|https://swdd01-mscdn.manage.microsoft.com/|'
    'Recommended|Intune|https://imeswdb-afd-primary.manage.microsoft.com/|'
    'Recommended|Intune|https://imeswdb-afd-secondary.manage.microsoft.com/|'

    # --- Activation / licensing (Windows Enterprise/Education step-up) ---
    'Required|Activation / licensing|https://licensing.mp.microsoft.com/|'
    'Required|Activation / licensing|https://licensing.md.mp.microsoft.com/|'
    'Required|Activation / licensing|https://purchase.mp.microsoft.com/|'
    'Required|Activation / licensing|https://displaycatalog.mp.microsoft.com/|'
    'Required|Activation / licensing|https://activation-v2.sls.microsoft.com/|'
    'Required|Activation / licensing|https://validation-v2.sls.microsoft.com/|'

    # --- Windows Update / Store / Delivery Optimisation (OOBE update check, ESP apps) ---
    'Required|Windows Update / Store|https://fe3.delivery.mp.microsoft.com/|'
    'Required|Windows Update / Store|https://sls.update.microsoft.com/|'
    'Recommended|Windows Update / Store|https://fe2.update.microsoft.com/|'
    'Recommended|Windows Update / Store|https://update.microsoft.com/|'
    'Required|Windows Update / Store|http://download.windowsupdate.com/|'
    'Recommended|Windows Update / Store|http://dl.delivery.mp.microsoft.com/|'
    'Recommended|Windows Update / Store|https://tsfe.trafficshaping.dsp.mp.microsoft.com/|'
    'Recommended|Windows Update / Store|https://geo.prod.do.dsp.mp.microsoft.com/|'
    'Recommended|Windows Update / Store|https://storeedgefd.dsx.mp.microsoft.com/|'
)

# Domains to give the filter admin: allow + exclude from SSL inspection + exclude from user authentication.
$RecommendedAllowList = @(
    '*.msftconnecttest.com', '*.msftncsi.com',
    '*.microsoft.com', '*.windows.com', '*.windows.net', '*.windowsupdate.com',
    '*.live.com', '*.microsoftonline.com', '*.microsoftonline-p.com', '*.microsoftonline-p.net',
    '*.msauth.net', '*.msftauth.net', '*.msauthimages.net', '*.msftauthimages.net',
    '*.microsoftazuread-sso.com', '*.windowsazure.com',
    '*.manage.microsoft.com', '*.dm.microsoft.com', '*.dds.microsoft.com',
    '*.mp.microsoft.com', '*.sls.microsoft.com', '*.update.microsoft.com', '*.data.microsoft.com',
    '*.microsoftaik.azure.net', 'ekop.intel.com', 'ftpm.amd.com',
    '*.digicert.com', '*.msocsp.com',
    'time.windows.com (UDP 123)'
)
#endregion

#region Per-endpoint test (runs in a runspace)
$TestEndpoint = {
    param([hashtable]$Ep, [int]$TimeoutMs)

    # Roots that public Microsoft endpoints chain to. Anything else = someone is re-signing the traffic.
    $ExpectedRootPattern = 'Microsoft|DigiCert|Baltimore|GlobalSign|Sectigo|USERTrust|COMODO|AAA Certificate Services|ISRG|Entrust|GeoTrust|Go Daddy|Starfield|Amazon|IdenTrust|GTS Root|Google Trust'
    $VendorPattern = 'Smoothwall|Lightspeed|Netsweeper|Fortinet|FortiGate|FortiGuard|Sophos|Securly|iboss|Zscaler|Palo ?Alto|Cisco|Umbrella|OpenDNS|ContentKeeper|Linewize|Qoria|Censornet|Barracuda|WatchGuard|SonicWall|Untangle|Forcepoint|Websense|Bloxx|Cyberoam|Check ?Point|Meraki|DNSFilter|SafetyNet|Surfprotect|Securus|Exa Networks|Netgear|Ubiquiti|pfSense|Squid'
    $BlockPagePattern = "$VendorPattern|web ?filter|content ?filter|site (has been )?blocked|(page|site|website|url) (is|has been) blocked|blocked by|request (was|has been) blocked|policy violation|captive portal|guest (wifi|network) login|accept the terms"
    $MsHostPattern = '(^|\.)(microsoft|windows|windowsupdate|msftconnecttest|msftncsi|live|msauth|msftauth|msauthimages|msftauthimages|microsoftonline|microsoftonline-p|windowsazure|azure|azureedge|azurefd|digicert|msocsp|office|bing|akamaized|akamaiedge|microsoftazuread-sso|intel|amd)\.(com|net|ms)$|^mscom\.errorpage\.failover\.com$'

    $r = [ordered]@{
        Level = $Ep.Level; Category = $Ep.Category; HostName = $Ep.HostName; Port = $Ep.Port; Scheme = $Ep.Scheme
        DNS = ''; IP = ''; TCP = ''; TLS = ''; CertIssuer = ''; HTTP = ''; Result = 'PASS'; Detail = ''
    }
    $notes = New-Object System.Collections.Generic.List[string]

    # ---------- DNS ----------
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Ep.HostName)
        $r.DNS = 'OK'
    } catch {
        $dnsErr = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $alt = ''
        try {
            $pub = Resolve-DnsName -Name $Ep.HostName -Server 1.1.1.1 -DnsOnly -QuickTimeout -ErrorAction Stop |
                   Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($pub) { $alt = " Resolves fine via public DNS 1.1.1.1 ($($pub.IPAddress)) -> the local DNS server/filter is blocking this name." }
        } catch {
            $alt = ' Also fails against public DNS 1.1.1.1 (name may not exist, or outbound DNS is blocked).'
        }
        $r.DNS = 'FAIL'; $r.Result = 'FAIL'; $r.Detail = "DNS lookup failed: $dnsErr.$alt"
        return [pscustomobject]$r
    }

    $r.IP = (($addrs | Select-Object -First 3) | ForEach-Object { $_.IPAddressToString }) -join ', '
    $sink = $addrs | Where-Object { $s = $_.IPAddressToString; $s -eq '0.0.0.0' -or $s -like '127.*' -or $s -eq '::' -or $s -eq '::1' }
    if ($sink) {
        $r.DNS = 'SINKHOLED'; $r.Result = 'FAIL'
        $r.Detail = "DNS returns $($r.IP) - the DNS filter is sinkholing this name."
        return [pscustomobject]$r
    }
    $private = $addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }
    if ($private) {
        $r.DNS = 'PRIVATE IP'
        $notes.Add("Resolves to private IP $($r.IP) - likely a DNS-based block page or internal override.")
    }

    $v4 = @($addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' })
    $v6 = @($addrs | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' })
    if ($Ep.Family -eq 'IPv6') { $target = $v6 | Select-Object -First 1 }
    elseif ($v4.Count) { $target = $v4[0] }
    else { $target = $v6 | Select-Object -First 1 }
    if (-not $target) {
        $r.Result = 'FAIL'; $r.Detail = "No usable $($Ep.Family) address returned."
        return [pscustomobject]$r
    }

    $client = $null; $ssl = $null
    try {
        # ---------- TCP ----------
        $client = New-Object System.Net.Sockets.TcpClient($target.AddressFamily)
        try {
            $iar = $client.BeginConnect($target, $Ep.Port, $null, $null)
            if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "timed out after $TimeoutMs ms (packets dropped by firewall)" }
            $client.EndConnect($iar)
            $r.TCP = 'OK'
        } catch {
            $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            $r.TCP = 'FAIL'; $r.Result = 'FAIL'; $r.Detail = "TCP $($Ep.Port) to $target failed: $msg"
            return [pscustomobject]$r
        }

        $client.ReceiveTimeout = $TimeoutMs; $client.SendTimeout = $TimeoutMs
        $net = $client.GetStream()
        $net.ReadTimeout = $TimeoutMs; $net.WriteTimeout = $TimeoutMs
        $io = $net

        # ---------- TLS ----------
        if ($Ep.Scheme -eq 'https') {
            $state = @{ Errors = '' }
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
                param($snd, $crt, $chn, $errs)
                $state.Errors = [string]$errs
                $true   # accept everything so we can inspect what we were given
            }
            $ssl = New-Object System.Net.Security.SslStream($net, $false, $cb)
            try {
                $ssl.AuthenticateAsClient($Ep.HostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            } catch {
                $e = $_.Exception
                while ($e.InnerException) { $e = $e.InnerException }
                $r.TLS = 'FAIL'; $r.Result = 'FAIL'
                $r.Detail = "TLS handshake failed: $($e.Message) - typically the filter resetting the connection after reading the SNI hostname."
                return [pscustomobject]$r
            }
            $r.TLS = ($ssl.SslProtocol.ToString() -replace 'Tls', 'TLS ' -replace '(\d)(\d)$', '$1.$2')

            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = 'NoCheck'
            [void]$chain.Build($cert)
            $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
            $cn = { param($dn) if ($dn -match 'CN=([^,]+)') { $Matches[1] } elseif ($dn -match 'O=([^,]+)') { $Matches[1] } else { $dn } }
            $issuerCN = & $cn $cert.Issuer
            $rootCN = & $cn $root.Subject
            $r.CertIssuer = "$issuerCN  (root: $rootCN)"

            if (("$($cert.Issuer) $($root.Subject)") -match $VendorPattern) {
                $r.TLS = 'INSPECTED'; $r.Result = 'FAIL'
                $r.Detail = "TLS inspection detected - certificate issued by '$issuerCN' (filter CA). Exclude this domain from SSL inspection."
                return [pscustomobject]$r
            }
            if ($root.Subject -notmatch $ExpectedRootPattern) {
                $r.TLS = 'INSPECTED?'; $r.Result = 'FAIL'
                $r.Detail = "Unexpected certificate chain '$issuerCN' -> '$rootCN' - looks like TLS inspection. A new device will not trust this. Exclude from SSL inspection."
                return [pscustomobject]$r
            }
            # Chain is genuine at this point, so a filter did not produce it. A name mismatch on a genuine
            # Microsoft cert just means the bare hostname isn't on the cert (normal for some CNAME-only names).
            $certErr = ($state.Errors -split ',\s*') | Where-Object { $_ -and $_ -ne 'None' -and $_ -ne 'RemoteCertificateNameMismatch' }
            if ($certErr) {
                $r.TLS = 'CERT ERROR'; $r.Result = 'FAIL'
                $r.Detail = "Certificate chain problem: $($certErr -join ', ') (issuer '$issuerCN'). Device may be missing root updates (check ctldl.windowsupdate.com)."
                return [pscustomobject]$r
            }
            if ($state.Errors -match 'NameMismatch') { $notes.Add('Genuine Microsoft certificate (hostname not listed on it - normal for this name).') }
            $io = $ssl
        }

        # ---------- HTTP ----------
        $ua = if ($Ep.Category -like 'NCSI*') { 'Microsoft NCSI' } else { 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OOBE-ConnectivityTest/1.0' }
        $req = "GET $($Ep.Path) HTTP/1.1`r`nHost: $($Ep.HostName)`r`nUser-Agent: $ua`r`nAccept: */*`r`nCache-Control: no-cache`r`nConnection: close`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $io.Write($bytes, 0, $bytes.Length); $io.Flush()

        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 8192
        $readBody = ($Ep.Scheme -eq 'http') -or $Ep.Expect
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            while ($sw.ElapsedMilliseconds -lt ($TimeoutMs * 2)) {
                $n = $io.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $ms.Write($buf, 0, $n)
                $sofar = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                $he = $sofar.IndexOf("`r`n`r`n")
                if ($he -ge 0) {
                    if (-not $readBody) { break }
                    $bodyLen = $ms.Length - ($he + 4)
                    if ($sofar -match '(?im)^Content-Length:\s*(\d+)') {
                        if ($bodyLen -ge [Math]::Min([int64]$Matches[1], 16384)) { break }
                    } elseif ($bodyLen -ge 16384) { break }
                }
            }
        } catch { }   # read timeout / reset after partial data is fine

        $text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        if ($text -notmatch '^HTTP/\d(\.\d)?\s+(\d{3})') {
            if ($Ep.Scheme -eq 'https') {
                $r.HTTP = 'no reply'
                $notes.Add('TLS OK with genuine certificate; service did not answer the generic probe (normal for some APIs).')
            } else {
                $r.HTTP = 'no reply'; $r.Result = 'FAIL'
                $notes.Add('TCP connected but no HTTP response - transparent proxy/filter is holding or dropping the request.')
            }
        } else {
            $status = [int]$Matches[2]
            $r.HTTP = $status
            $he = $text.IndexOf("`r`n`r`n")
            $headers = if ($he -ge 0) { $text.Substring(0, $he) } else { $text }
            $body = if ($he -ge 0) { $text.Substring($he + 4) } else { '' }

            if ($headers -match '(?im)^Location:\s*(\S+)') {
                $loc = $Matches[1]
                if ($loc -match '^https?://([^/:?#]+)' -and $Matches[1] -notmatch $MsHostPattern) {
                    $r.Result = 'FAIL'
                    $notes.Add("Redirected to $loc - captive portal / filter block page / auth page.")
                }
            }
            # Only plain HTTP can be tampered with if the TLS cert was genuine
            if ($Ep.Scheme -eq 'http') {
                if ($body -match $BlockPagePattern -or $headers -match "(?im)^(Server|Via|X-[\w-]+):.*($VendorPattern)") {
                    $r.Result = 'FAIL'
                    $notes.Add('Response looks like a filter block page / captive portal (vendor or block keywords found).')
                }
            }
            if ($Ep.Expect) {
                if ($body.Trim() -ne $Ep.Expect) {
                    $snippet = ($body -replace '\s+', ' ').Trim()
                    if ($snippet.Length -gt 100) { $snippet = $snippet.Substring(0, 100) + '...' }
                    $r.Result = 'FAIL'
                    $notes.Add("Expected body '$($Ep.Expect)' but got HTTP $status '$snippet'. Windows will think there is NO internet.")
                }
            }
        }
    } catch {
        $r.Result = 'FAIL'
        $notes.Add("Unexpected error: $($_.Exception.Message)")
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($client) { $client.Close() }
    }

    if ($r.Result -eq 'PASS' -and $r.DNS -eq 'PRIVATE IP') { $r.Result = 'WARN' }
    $r.Detail = $notes -join ' '
    [pscustomobject]$r
}
#endregion

#region Helpers
function Write-Section($title) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Write-Result($result, $label, $detail) {
    $color = switch ($result) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'INFO' { 'Gray' } default { 'Red' } }
    Write-Host ('[{0,-4}] ' -f $result) -ForegroundColor $color -NoNewline
    Write-Host ('{0,-52}' -f $label) -NoNewline
    Write-Host " $detail" -ForegroundColor DarkGray
}

function Test-Ntp([string]$Server, [int]$Timeout) {
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $Timeout
        $udp.Connect($Server, 123)
        $pkt = New-Object byte[] 48
        $pkt[0] = 0x1B   # LI=0, VN=3, Mode=3 (client)
        [void]$udp.Send($pkt, $pkt.Length)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)
        $sec = [BitConverter]::ToUInt32([byte[]]($resp[43], $resp[42], $resp[41], $resp[40]), 0)
        $frac = [BitConverter]::ToUInt32([byte[]]($resp[47], $resp[46], $resp[45], $resp[44]), 0)
        $ntpTime = (New-Object DateTime(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddSeconds($sec).AddMilliseconds($frac * 1000.0 / 4294967296)
        [pscustomobject]@{ Ok = $true; Offset = ($ntpTime - [DateTime]::UtcNow).TotalSeconds; Error = $null }
    } catch {
        [pscustomobject]@{ Ok = $false; Offset = $null; Error = $_.Exception.Message }
    } finally { $udp.Close() }
}
#endregion

#region Environment / network summary
$start = Get-Date
Write-Section "OOBE / Autopilot connectivity test - $env:COMPUTERNAME - $($start.ToString('yyyy-MM-dd HH:mm'))"

$ssid = $null
try {
    $wlan = netsh wlan show interfaces 2>$null
    $m = $wlan | Select-String '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1
    if ($m) { $ssid = $m.Matches[0].Groups[1].Value.Trim() }
} catch { }

$generalFindings = New-Object System.Collections.Generic.List[object]
function Add-General($result, $name, $detail) {
    $generalFindings.Add([pscustomobject]@{ Level = 'Critical'; Category = 'General'; HostName = $name; Port = ''; Scheme = ''
            DNS = ''; IP = ''; TCP = ''; TLS = ''; CertIssuer = ''; HTTP = ''; Result = $result; Detail = $detail })
    Write-Result $result $name $detail
}

$cfg = $null
try { $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway } | Select-Object -First 1 } catch { }
$hasIPv6 = $false
if ($cfg) {
    $v4 = ($cfg.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', '
    $gw = ($cfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
    $dnsSrv = ($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', '
    $g6 = Get-NetIPAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.PrefixOrigin -ne 'WellKnown' }
    $hasIPv6 = [bool]($g6 -and $cfg.IPv6DefaultGateway)
    Write-Host ("  Adapter   : {0}{1}" -f $cfg.InterfaceAlias, $(if ($ssid) { "  (SSID: $ssid)" }))
    Write-Host "  IPv4      : $v4   Gateway: $gw"
    Write-Host "  DNS       : $dnsSrv"
    Write-Host ("  IPv6      : {0}" -f $(if ($hasIPv6) { ($g6 | Select-Object -First 1).IPAddress + ' (global IPv6 present)' } else { 'none' }))
} else {
    Write-Host '  No adapter with a default gateway found!' -ForegroundColor Red
}

$winhttp = ((netsh winhttp show proxy) | Where-Object { $_ -match '\S' } | Select-Object -Skip 1) -join ' '
Write-Host "  WinHTTP   : $($winhttp.Trim())"
$ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($ie -and ($ie.ProxyEnable -eq 1 -or $ie.AutoConfigURL)) {
    Write-Host "  User proxy: Enabled=$($ie.ProxyEnable) Server=$($ie.ProxyServer) PAC=$($ie.AutoConfigURL)" -ForegroundColor Yellow
    Write-Host '              NOTE: OOBE has no proxy. This script tests DIRECT connections, as OOBE does.' -ForegroundColor Yellow
}
Write-Host "  PowerShell: $($PSVersionTable.PSVersion)   OS: $([Environment]::OSVersion.Version)"
#endregion

#region General checks
Write-Section 'General checks'

# What Windows itself currently thinks
try {
    $prof = Get-NetConnectionProfile -ErrorAction Stop | Select-Object -First 1
    if ($prof) {
        $res = if ($prof.IPv4Connectivity -eq 'Internet' -or $prof.IPv6Connectivity -eq 'Internet') { 'PASS' } else { 'FAIL' }
        Add-General $res 'Windows NCSI status (Get-NetConnectionProfile)' "IPv4=$($prof.IPv4Connectivity) IPv6=$($prof.IPv6Connectivity). OOBE needs 'Internet' here."
    }
} catch { }

# NCSI DNS probe
try {
    $ncsiIp = [System.Net.Dns]::GetHostAddresses('dns.msftncsi.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if ("$ncsiIp" -eq '131.107.255.255') { Add-General 'PASS' 'NCSI DNS probe dns.msftncsi.com' '131.107.255.255 as expected' }
    else { Add-General 'FAIL' 'NCSI DNS probe dns.msftncsi.com' "Got '$ncsiIp', expected 131.107.255.255 - DNS is being rewritten." }
} catch { Add-General 'FAIL' 'NCSI DNS probe dns.msftncsi.com' "Lookup failed: $($_.Exception.InnerException.Message)" }

# Time
$ntp = Test-Ntp 'time.windows.com' $TimeoutMs
if ($ntp.Ok) {
    $off = [Math]::Round($ntp.Offset, 1)
    if ([Math]::Abs($off) -gt 300) { Add-General 'FAIL' 'NTP time.windows.com (UDP 123)' "Reachable, but local clock is off by $off s - TLS/Entra sign-in will fail. Fix the clock/BIOS time." }
    else { Add-General 'PASS' 'NTP time.windows.com (UDP 123)' "Clock offset $off s" }
} else {
    Add-General 'WARN' 'NTP time.windows.com (UDP 123)' "No reply ($($ntp.Error)). UDP 123 blocked - fine only if the device clock is already correct. Local UTC: $([DateTime]::UtcNow.ToString('u'))"
}
#endregion

#region Build endpoint objects
$endpoints = foreach ($line in $EndpointDefs) {
    $p = $line.Split('|')
    $u = [Uri]$p[2]
    @{ Level = $p[0]; Category = $p[1]; Scheme = $u.Scheme; HostName = $u.Host; Port = $u.Port; Path = $u.PathAndQuery; Expect = $p[3]; Family = 'Any' }
}
if ($hasIPv6) {
    $endpoints = @(@{ Level = 'Recommended'; Category = 'NCSI (connectivity check)'; Scheme = 'http'; HostName = 'ipv6.msftconnecttest.com'; Port = 80
            Path = '/connecttest.txt'; Expect = 'Microsoft Connect Test'; Family = 'IPv6' }) + $endpoints
}
#endregion

#region Run tests in parallel
$pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
$pool.Open()
$jobs = foreach ($ep in $endpoints) {
    $ps = [powershell]::Create().AddScript($TestEndpoint).AddArgument($ep).AddArgument($TimeoutMs)
    $ps.RunspacePool = $pool
    [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Ep = $ep }
}
do {
    $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
    Write-Progress -Activity 'Testing Microsoft endpoints' -Status "$done / $($jobs.Count)" -PercentComplete ($done / $jobs.Count * 100)
    if ($done -lt $jobs.Count) { Start-Sleep -Milliseconds 250 }
} while ($done -lt $jobs.Count)
Write-Progress -Activity 'Testing Microsoft endpoints' -Completed

$results = foreach ($j in $jobs) {
    $out = $j.PS.EndInvoke($j.Handle)
    if ($out) { $out | Select-Object -Last 1 }
    else {
        $err = ($j.PS.Streams.Error | Select-Object -First 1)
        [pscustomobject]@{ Level = $j.Ep.Level; Category = $j.Ep.Category; HostName = $j.Ep.HostName; Port = $j.Ep.Port; Scheme = $j.Ep.Scheme
            DNS = ''; IP = ''; TCP = ''; TLS = ''; CertIssuer = ''; HTTP = ''; Result = 'FAIL'; Detail = "Test error: $err" }
    }
    $j.PS.Dispose()
}
$pool.Close(); $pool.Dispose()

# Failures on Recommended endpoints are warnings
foreach ($r in $results) { if ($r.Level -eq 'Recommended' -and $r.Result -eq 'FAIL') { $r.Result = 'WARN' } }
#endregion

#region Baseline comparison
$baseline = @{}
if ($BaselineCsv) {
    if (Test-Path $BaselineCsv) {
        Import-Csv $BaselineCsv | ForEach-Object { $baseline["$($_.Scheme)|$($_.HostName)|$($_.Port)"] = $_.Result }
    } else { Write-Warning "Baseline file not found: $BaselineCsv" }
}
foreach ($r in $results) {
    $b = $baseline["$($r.Scheme)|$($r.HostName)|$($r.Port)"]
    $r | Add-Member -NotePropertyName Baseline -NotePropertyValue $(if ($b) { $b } else { '' })
}
#endregion

#region Output
foreach ($grp in ($results | Group-Object Category)) {
    $okCount = @($grp.Group | Where-Object { $_.Result -eq 'PASS' }).Count
    if (-not $ShowAll) {
        $color = if ($okCount -eq $grp.Count) { 'Green' } elseif (@($grp.Group | Where-Object { $_.Result -eq 'FAIL' })) { 'Red' } else { 'Yellow' }
        Write-Host ''
        Write-Host (' {0,-40} {1,2} / {2,-2} OK' -f $grp.Name, $okCount, $grp.Count) -ForegroundColor $color
    } else {
        Write-Section $grp.Name
    }
    foreach ($r in $grp.Group) {
        if (-not $ShowAll) { continue }   # problems are listed once, in the final summary
        $label = '{0}://{1}:{2}' -f $r.Scheme, $r.HostName, $r.Port
        if ($label.Length -gt 52) { $label = $label.Substring(0, 49) + '...' }
        $info = @()
        if ($r.Result -eq 'PASS') {
            if ($r.TLS) { $info += $r.TLS }
            if ($r.HTTP) { $info += "HTTP $($r.HTTP)" }
            if ($r.CertIssuer) { $info += $r.CertIssuer }
        }
        if ($r.Detail) { $info += $r.Detail }
        if ($r.Baseline -eq 'PASS' -and $r.Result -ne 'PASS') { $info = @('<< WORKS ON BASELINE NETWORK >>') + $info }
        Write-Result $r.Result $label ($info -join ' | ')
    }
}

$all = @($generalFindings.ToArray()) + @($results)
$fails = @($all | Where-Object { $_.Result -eq 'FAIL' })
$warns = @($all | Where-Object { $_.Result -eq 'WARN' })
$passes = @($all | Where-Object { $_.Result -eq 'PASS' })

# Diagnosis hints
$hints = New-Object System.Collections.Generic.List[string]
if ($all | Where-Object { $_.Category -like 'NCSI*' -or $_.HostName -like '*NCSI*' } | Where-Object { $_.Result -eq 'FAIL' }) {
    $hints.Add('NCSI is failing: Windows decides there is no internet, which is exactly what makes OOBE show "Sorry, you''ve lost connection". Allow www.msftconnecttest.com / dns.msftncsi.com over HTTP (port 80) for UNAUTHENTICATED devices, with no redirect, captive portal or block page.')
}
if ($results | Where-Object { $_.TLS -like 'INSPECTED*' }) {
    $issuers = ($results | Where-Object { $_.TLS -like 'INSPECTED*' } | ForEach-Object { ($_.CertIssuer -split '  ')[0] } | Sort-Object -Unique) -join ', '
    $hints.Add("TLS/SSL inspection is active (issuer: $issuers). A new device in OOBE does not have the filter's CA, and Autopilot/Entra/Intune/Windows Update are certificate-pinned, so these domains MUST be excluded from SSL inspection.")
}
if ($results | Where-Object { $_.DNS -in 'FAIL', 'SINKHOLED', 'PRIVATE IP' -and $_.Result -ne 'PASS' }) {
    $hints.Add('Some names are blocked at DNS level - check the DNS filter policy (and that the DNS server forwards these zones).')
}
if ($results | Where-Object { $_.TCP -eq 'FAIL' }) {
    $hints.Add('Some connections are dropped at TCP level - check the firewall rules for the Wi-Fi VLAN / guest network.')
}
if ($results | Where-Object { $_.Detail -match 'Redirected to|block page|captive portal' }) {
    $hints.Add('Requests are being redirected / served a block page. Common cause: the filter applies a "not logged in / unauthenticated" policy to unknown devices. New devices in OOBE cannot authenticate to the filter, so the domains below must be allowed for unauthenticated users (or the onboarding SSID/VLAN must bypass authentication).')
}
# Save files (quietly - the terminal output below is the main report)
if (-not $OutputPath) { $OutputPath = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP } }
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$tag = if ($ssid) { $ssid -replace '[^\w\-]', '_' } else { 'wired' }
$stamp = $start.ToString('yyyyMMdd-HHmm')
$csv = Join-Path $OutputPath "OOBE-Connectivity_$($env:COMPUTERNAME)_$($tag)_$stamp.csv"
$txt = Join-Path $OutputPath "OOBE-Connectivity_$($env:COMPUTERNAME)_$($tag)_$stamp`_ForFilterAdmin.txt"
try {
    $all | Select-Object Result, Level, Category, Scheme, HostName, Port, DNS, IP, TCP, TLS, CertIssuer, HTTP, Baseline, Detail |
        Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
} catch {
    $OutputPath = $env:TEMP
    $csv = Join-Path $OutputPath (Split-Path $csv -Leaf); $txt = Join-Path $OutputPath (Split-Path $txt -Leaf)
    $all | Select-Object Result, Level, Category, Scheme, HostName, Port, DNS, IP, TCP, TLS, CertIssuer, HTTP, Baseline, Detail |
        Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
}

$report = @()
$report += "OOBE connectivity test - $env:COMPUTERNAME - SSID: $ssid - $($start.ToString('yyyy-MM-dd HH:mm'))"
$report += ''
$report += 'FAILED / WARNING endpoints on this network:'
$report += ($fails + $warns | ForEach-Object { "  [$($_.Result)] $($_.Scheme)://$($_.HostName):$($_.Port)  - $($_.Detail)" })
$report += ''
$report += 'Diagnosis:'
$report += ($hints | ForEach-Object { "  * $_" })
$report += ''
$report += 'Recommended configuration for the web filter / firewall (for the SSID/VLAN new devices join):'
$report += '  1. ALLOW the domains below for unauthenticated / unknown devices (no login page, no captive portal).'
$report += '  2. EXCLUDE them from SSL/TLS inspection (decryption) - many are certificate-pinned.'
$report += '  3. Allow outbound TCP 80 + 443 and UDP 123 (NTP) to them.'
$report += '  4. Do not redirect or rewrite HTTP for *.msftconnecttest.com / *.msftncsi.com (Windows connectivity check).'
$report += ''
$report += ($RecommendedAllowList | ForEach-Object { "  $_" })
$report += ''
$report += 'Reference: https://learn.microsoft.com/autopilot/requirements?tabs=networking'
$report += '           https://learn.microsoft.com/intune/intune-service/fundamentals/intune-endpoints'
try { $report | Set-Content -Path $txt -Encoding UTF8 -ErrorAction Stop } catch { $txt = $null }

# ---------- Final on-screen summary: everything needed without scrolling ----------
Write-Section ("RESULT on '{0}':  PASS {1}   WARN {2}   FAIL {3}" -f $(if ($ssid) { $ssid } else { 'wired' }), $passes.Count, $warns.Count, $fails.Count)

$rank = @{ Critical = 0; Required = 1; Recommended = 2 }
if ($fails) {
    Write-Host ' FAILED (most important first):' -ForegroundColor Red
    foreach ($p in ($fails | Sort-Object { $rank[$_.Level] })) {
        $what = if ($p.Port) { '{0}:{1}' -f $p.HostName, $p.Port } else { $p.HostName }
        $tagTxt = if ($p.Baseline -eq 'PASS') { ' [works on baseline]' } else { '' }
        Write-Host (' {0,-8} {1}{2}' -f $p.Level, $what, $tagTxt) -ForegroundColor Red -NoNewline
        Write-Host " - $($p.Detail)" -ForegroundColor DarkGray
    }
    Write-Host ''
}
if ($warns) {
    Write-Host ' WARNINGS (non-critical):' -ForegroundColor Yellow
    if ($warns.Count -le 5 -or $ShowAll) {
        foreach ($p in $warns) {
            Write-Host " $($p.HostName):$($p.Port)" -ForegroundColor Yellow -NoNewline
            Write-Host " - $($p.Detail)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host (' ' + (($warns | ForEach-Object { $_.HostName }) -join ', ')) -ForegroundColor Yellow
        Write-Host ' (same kind of failure as above - run with -ShowAll for details)' -ForegroundColor DarkGray
    }
    Write-Host ''
}

if ($hints.Count) {
    Write-Host ' Diagnosis:' -ForegroundColor Yellow
    $hints | ForEach-Object { Write-Host "  * $_" -ForegroundColor Yellow }
    Write-Host ''
}

$critFails = @($fails | Where-Object { $_.Level -eq 'Critical' })
if ($critFails) {
    Write-Host ' VERDICT: Critical endpoints are blocked - this network WILL break OOBE ("Sorry, you''ve lost connection").' -ForegroundColor Red
} elseif ($fails) {
    Write-Host ' VERDICT: OOBE may get past the network screen, but Autopilot / enrolment / activation will fail or stall.' -ForegroundColor Red
} elseif ($warns) {
    Write-Host ' VERDICT: Nothing critical blocked. Warnings only affect later steps (apps, updates, branding).' -ForegroundColor Yellow
} else {
    Write-Host ' VERDICT: Everything Microsoft needs is reachable from this device on this network.' -ForegroundColor Green
    Write-Host '          If OOBE still fails, run this on the NEW device from OOBE (Shift+F10) - a managed device' -ForegroundColor Green
    Write-Host '          may trust the filter CA or get a different filter policy than an unknown device.' -ForegroundColor Green
}
Write-Host ''
Write-Host " Saved: $csv" -ForegroundColor DarkGray
if (-not $BaselineCsv) {
    Write-Host " Compare with another network: re-run with  -BaselineCsv `"$csv`"" -ForegroundColor DarkGray
}
if (-not $ShowAll) { Write-Host ' Add -ShowAll to list every endpoint (incl. passing ones).' -ForegroundColor DarkGray }
#endregion
