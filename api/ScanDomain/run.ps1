{\rtf1\ansi\ansicpg1252\cocoartf2709
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 using namespace System.Net\
\
param($Request, $TriggerMetadata)\
\
# 1. Extract and sanitize the domain parameter (e.g., ?domain=microsoft.com)\
$rawDomain = $Request.Query.domain\
if (-not $rawDomain -and $Request.Body.domain) \{\
    $rawDomain = $Request.Body.domain\
\}\
\
if (-not $rawDomain -or $rawDomain -notmatch '^[a-zA-Z0-9.-]+\\.[a-zA-Z]\{2,\}$') \{\
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@\{\
        StatusCode = [HttpStatusCode]::BadRequest\
        Body       = (@\{ error = "Invalid domain syntax. Usage: atv --scan-domain <company.com>" \} | ConvertTo-Json)\
    \})\
    return\
\}\
\
$domain = $rawDomain.Trim().ToLower()\
$score = 40 # Baseline score\
\
# 2. Query Microsoft Entra ID OpenID Connect Federation Endpoint\
$entraStatus = "Not Detected / Unfederated"\
$tenantId = "N/A"\
try \{\
    $oidcUrl = "https://login.microsoftonline.com/$domain/v2.0/.well-known/openid-configuration"\
    $oidc = Invoke-RestMethod -Uri $oidcUrl -Method Get -TimeoutSec 4 -ErrorAction Stop\
    if ($oidc.issuer) \{\
        $tenantId = ($oidc.issuer -split '/')[3]\
        $entraStatus = "Verified Microsoft Entra ID Tenant"\
        $score += 20\
    \}\
\} catch \{\
    $entraStatus = "External IdP or Consumer Domain"\
\}\
\
# 3. Query SPF TXT Records via DNS-over-HTTPS (Cloudflare 1.1.1.1 API)\
$spfStatus = "MISSING (High Spoofing Risk)"\
try \{\
    $dnsTxt = Invoke-RestMethod -Uri "https://cloudflare-dns.com/dns-query?name=$domain&type=TXT" -Headers @\{ "Accept" = "application/dns-json" \} -TimeoutSec 4\
    $spfRecord = $dnsTxt.Answer | Where-Object \{ $_.data -match "v=spf1" \} | Select-Object -First 1\
    if ($spfRecord) \{\
        if ($spfRecord.data -match "-all") \{\
            $spfStatus = "Hardened (-all Strict Enforcement)"\
            $score += 20\
        \} elseif ($spfRecord.data -match "~all") \{\
            $spfStatus = "SoftFail (~all Transition Mode)"\
            $score += 10\
        \} else \{\
            $spfStatus = "Permissive (Needs Remediation)"\
        \}\
    \}\
\} catch \{\}\
\
# 4. Query DMARC Policy (_dmarc.domain.com)\
$dmarcStatus = "MISSING (Exfiltration / Phishing Vulnerable)"\
try \{\
    $dnsDmarc = Invoke-RestMethod -Uri "https://cloudflare-dns.com/dns-query?name=_dmarc.$domain&type=TXT" -Headers @\{ "Accept" = "application/dns-json" \} -TimeoutSec 4\
    $dmarcRecord = $dnsDmarc.Answer | Where-Object \{ $_.data -match "v=DMARC1" \} | Select-Object -First 1\
    if ($dmarcRecord) \{\
        if ($dmarcRecord.data -match "p=reject") \{\
            $dmarcStatus = "Enforced (p=reject Zero-Trust Standard)"\
            $score += 20\
        \} elseif ($dmarcRecord.data -match "p=quarantine") \{\
            $dmarcStatus = "Quarantine Active (p=quarantine)"\
            $score += 15\
        \} else \{\
            $dmarcStatus = "Monitor Only (p=none \'97 Unenforced!)"\
            $score += 5\
        \}\
    \}\
\} catch \{\}\
\
# 5. Return Telemetry Payload to ATV_Console_v2.6\
$payload = [ordered]@\{\
    domain      = $domain\
    tenantId    = $tenantId\
    entraStatus = $entraStatus\
    spfStatus   = $spfStatus\
    dmarcStatus = $dmarcStatus\
    postureScore = "$score%"\
    timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")\
\}\
\
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@\{\
    StatusCode = [HttpStatusCode]::OK\
    Headers    = @\{ "Content-Type" = "application/json" \}\
    Body       = ($payload | ConvertTo-Json -Depth 4)\
\})}