# ---------------------------------------------------------------------------
# Shared internal helpers
# ---------------------------------------------------------------------------

Function Assert-SspiConnection {
    param($Connection)
    if (-not $Connection) {
        throw "No SSPI connection available. Run Connect-SspInstaller first (it sets the default connection automatically), or pass -Connection explicitly."
    }
    if ($Connection.PSTypeNames -notcontains 'Sspi.Connection') {
        throw "Expected a connection object from Connect-SspInstaller."
    }
}

Function Get-SspiAuthHeader {
    param([Parameter(Mandatory)][PSCredential]$Credential)
    $pair = "{0}:{1}" -f $Credential.UserName, $Credential.GetNetworkCredential().Password
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    return @{ Authorization = "Basic " + [Convert]::ToBase64String($bytes) }
}

Function Enable-SspiInsecureTls {
    # Windows PowerShell 5.1 has no per-call -SkipCertificateCheck; this is the
    # process-wide fallback (matches curl -k's scope: this session only).
    if (-not ("SspiTrustAllCertsPolicy" -as [type])) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SspiTrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object SspiTrustAllCertsPolicy
}

Function Add-SspiProgressStreamType {
    # A Stream wrapper that counts bytes as they're read, so upload progress
    # can be reported. Deliberately does NOT call back into PowerShell from
    # here — Read/ReadAsync run on whatever thread HttpClient's internals
    # choose, same runspace trap as the cert-callback bug above. Instead it
    # just increments a thread-safe counter; the caller polls TotalBytesRead
    # from the main PowerShell thread and drives Write-Progress itself.
    if (-not ("SspiProgressStream" -as [type])) {
        Add-Type @"
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
public class SspiProgressStream : Stream {
    private readonly Stream _inner;
    private long _totalRead;
    public SspiProgressStream(Stream inner) { _inner = inner; }
    public long TotalBytesRead { get { return Interlocked.Read(ref _totalRead); } }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { return _inner.Length; } }
    public override long Position { get { return _inner.Position; } set { throw new NotSupportedException(); } }
    public override void Flush() { _inner.Flush(); }
    public override int Read(byte[] buffer, int offset, int count) {
        int n = _inner.Read(buffer, offset, count);
        if (n > 0) { Interlocked.Add(ref _totalRead, n); }
        return n;
    }
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        int n = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        if (n > 0) { Interlocked.Add(ref _totalRead, n); }
        return n;
    }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
    public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    protected override void Dispose(bool disposing) {
        if (disposing) { _inner.Dispose(); }
        base.Dispose(disposing);
    }
}
"@
    }
}

Function Invoke-SspiApi {
    <#
    Single choke point for every non-upload SSPI call. Handles the
    -Troubleshoot printing so individual Get/New/Remove functions don't
    have to duplicate it.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [string]$BodyJson,
        [string]$RedactedBodyJson,
        [switch]$Troubleshoot
    )
    Assert-SspiConnection $Connection
    $uri = "$($Connection.BaseUrl)$Path"

    if ($Troubleshoot) {
        Write-Host "[TROUBLESHOOT] $Method $uri"
        $display = if ($RedactedBodyJson) { $RedactedBodyJson } else { $BodyJson }
        if ($display) { Write-Host $display }
    }

    $headers = Get-SspiAuthHeader -Credential $Connection.Credential
    # Tolerate an older/stale connection object that predates -TimeoutSec (property
    # would be $null, which Invoke-RestMethod rejects outright) by falling back to 15s.
    $timeoutSec = if ($Connection.TimeoutSec) { $Connection.TimeoutSec } else { 15 }
    $params = @{ Method = $Method; Uri = $uri; Headers = $headers; TimeoutSec = $timeoutSec }
    if ($BodyJson) { $params.Body = $BodyJson; $params.ContentType = 'application/json' }

    if ($Connection.Insecure) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { Enable-SspiInsecureTls }
    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            throw [System.Exception]::new(
                "Authentication failed (HTTP $statusCode) calling $Method $uri. Please re-authenticate using Connect-SspInstaller — your session/credentials are no longer valid.",
                $_.Exception)
        }

        $message = $_.ErrorDetails.Message
        if (-not $message -and $_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $message = $reader.ReadToEnd()
            }
            catch { }
        }
        if (-not $message) { $message = $_.Exception.Message }
        # Single clean terminating error instead of Write-Error + rethrow (which
        # duplicated the message on screen). Original exception kept as InnerException.
        throw [System.Exception]::new("SSPI API error ($Method $uri): $message", $_.Exception)
    }
}

Function Out-SspiResult {
    # Returns a clean, real PSCustomObject (or array of them) — nothing
    # printed here. List endpoints (GetAllX) wrap their payload in a
    # ListResult envelope ({offset, number_of_results, total_result_count,
    # total_pages, sort_ascending, sort_by, <payload array>}) — unwrap that
    # so callers just get the items, not the pagination shell. The payload
    # array's property name is NOT consistent across the API: bundles and
    # platforms call it "results", providers calls it "configs". So detect
    # the envelope by its pagination fields, then take whichever OTHER
    # top-level property holds the array, rather than hardcoding a name.
    #
    # Deliberately does NOT pretty-print via Write-Host: PowerShell's console
    # auto-formats whatever a function returns when it isn't captured into a
    # variable, so printing here as well just produces the same data twice —
    # once readable, once as the ugly default @{...} dump. Pipe the result
    # through `ConvertTo-Json -Depth 10` yourself when you want that view;
    # the object itself is untouched either way.
    param($Result)
    if ($null -eq $Result) { return $Result }
    $toReturn = $Result

    $listMetadataKeys = @('offset', 'number_of_results', 'total_result_count', 'total_pages', 'sort_ascending', 'sort_by')
    $propNames = @($Result.PSObject.Properties.Name)
    $looksLikeListResult = @($propNames | Where-Object { $listMetadataKeys -contains $_ }).Count -gt 0
    if ($looksLikeListResult) {
        $payloadProp = $propNames | Where-Object { $listMetadataKeys -notcontains $_ } | Select-Object -First 1
        if ($payloadProp) { $toReturn = $Result.$payloadProp }
    }

    return $toReturn
}

Function ConvertTo-PoolObject {
    # "start-end[:name]" -> ordered hashtable {start, end, [name]}
    param([Parameter(Mandatory)][string]$Value, [string]$FlagName = 'pool')
    if ($Value -notmatch '-') {
        throw "'$Value' for $FlagName is missing the '-' separator between start and end (use START-END or START-END:NAME)"
    }
    $rangeParts = $Value -split '-', 2
    $rest = $rangeParts[1] -split ':', 2
    if ($rest.Count -eq 2) {
        return [ordered]@{ start = $rangeParts[0]; end = $rest[0]; name = $rest[1] }
    }
    else {
        return [ordered]@{ start = $rangeParts[0]; end = $rest[0] }
    }
}

Function Copy-RedactedHashtable {
    # Manual copy + redact — [ordered]@{}.Clone() is unreliable across PS versions.
    param([Parameter(Mandatory)]$Source, [string[]]$RedactKeys)
    $copy = [ordered]@{}
    foreach ($key in $Source.Keys) { $copy[$key] = $Source[$key] }
    foreach ($key in $RedactKeys) { if ($copy.Contains($key)) { $copy[$key] = '********' } }
    return $copy
}

# ---------------------------------------------------------------------------
# Connect-SspInstaller
# ---------------------------------------------------------------------------

Function Connect-SspInstaller {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Connect to the SSP Installer (SSPI) API
        .DESCRIPTION
            Creates a connection object (host + credential) and sets it as the
            default for every other SspInstaller.ps1 function in this session.
            There is no server-side session here — this just packages what every
            other call needs and stashes it so you don't have to pass -Connection
            every time.
        .PARAMETER SspiHost
            The hostname/FQDN or IP address of the SSP Installer appliance
        .PARAMETER Credential
            Credential for the SSPI API (Basic auth). Prompted for if omitted.
        .PARAMETER Insecure
            Skip TLS certificate validation. Defaults to $true, matching a lab
            environment with self-signed certificates.
        .PARAMETER TimeoutSec
            Request timeout in seconds. Defaults to 15; raise it if you're on a
            slow link or hitting genuinely slow endpoints.

        .EXAMPLE
            Connect-SspInstaller -SspiHost ssp-inst01.vcf.lab
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SspiHost,
        [PSCredential]$Credential,
        [bool]$Insecure = $true,
        # Invoke-RestMethod's own default (~100s) makes real connectivity
        # problems look like a hang. 15s surfaces them fast; raise it if
        # you're on a slow link or hitting genuinely slow endpoints.
        [int]$TimeoutSec = 15
    )
    if (-not $Credential) {
        $Credential = Get-Credential -Message "SSPI credentials for https://$SspiHost/sspi" -UserName 'admin'
    }
    $conn = [PSCustomObject]@{
        PSTypeName = 'Sspi.Connection'
        SspiHost   = $SspiHost
        BaseUrl    = "https://$SspiHost/sspi"
        Credential = $Credential
        Insecure   = $Insecure
        TimeoutSec = $TimeoutSec
    }
    $script:SspiConnection = $conn
    Write-Host "Default SSPI connection set: $($conn.BaseUrl) (user: $($Credential.UserName)). Pass -Connection to override for a specific call."
    return $conn
}

# ---------------------------------------------------------------------------
# End User License Agreement: GET /sspi/eula/content, GET/POST /sspi/eula/acceptance
# ---------------------------------------------------------------------------

Function Get-SspInstallerEula {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns the SSP End User License Agreement text or its acceptance status
        .DESCRIPTION
            By default, this cmdlet returns whether the EULA has been accepted on
            this SSPI instance. Pass -Content to instead return the full EULA
            text. Use Approve-SspInstallerEula to accept it.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER Content
            Return the full EULA text instead of the acceptance status
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Get-SspInstallerEula

        .EXAMPLE
            Get-SspInstallerEula -Content
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [switch]$Content,
        [switch]$Troubleshoot
    )
    $path = if ($Content) { '/eula/content' } else { '/eula/acceptance' }
    Out-SspiResult (Invoke-SspiApi -Connection $Connection -Method GET -Path $path -Troubleshoot:$Troubleshoot)
}

Function Approve-SspInstallerEula {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Accepts the SSP End User License Agreement
        .DESCRIPTION
            This cmdlet POSTs acceptance of the SSP End User License Agreement
            to SSPI. This must be accepted before a platform can be deployed
            (see New-SspInstallerDeployment). Use Get-SspInstallerEula to review
            the EULA text or check its current acceptance status first.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Approve-SspInstallerEula
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [switch]$Troubleshoot
    )
    Invoke-SspiApi -Connection $Connection -Method POST -Path '/eula/acceptance' -Troubleshoot:$Troubleshoot
    Write-Host "EULA successfully accepted."
}

# ---------------------------------------------------------------------------
# vCenter provider registration: POST/GET/DELETE /sspi/providers
# ---------------------------------------------------------------------------

Function New-SspInstallerVCenterServer {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Register a vCenter Server with the SSP Installer
        .DESCRIPTION
            This cmdlet registers (POSTs) a vCenter Server as a provider in SSPI
            so it can later be used as the deployment target for
            New-SspInstallerDeployment.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER VCenterServer
            The hostname/FQDN or IP address of the vCenter Server to register
        .PARAMETER VCenterCredential
            Credential for the vCenter Server. Prompted for if omitted.
        .PARAMETER CertificateFile
            Path to a PEM-encoded certificate file to trust for this vCenter
            Server. Optional.
        .PARAMETER Troubleshoot
            Print the HTTP method, URI, and request body (with secrets redacted)
            sent to the API, without affecting the actual request.

        .EXAMPLE
            New-SspInstallerVCenterServer -VCenterServer vc.vcf.lab

        .EXAMPLE
            New-SspInstallerVCenterServer -VCenterServer vc.vcf.lab -CertificateFile ~/Desktop/certs/vc.crt
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$VCenterServer,
        [PSCredential]$VCenterCredential,
        [string]$CertificateFile,
        [switch]$Troubleshoot
    )
    Assert-SspiConnection $Connection
    if (-not $VCenterCredential) {
        $VCenterCredential = Get-Credential -Message "vCenter credentials for $VCenterServer"
    }
    $cert = $null
    if ($CertificateFile) {
        if (-not (Test-Path $CertificateFile)) { throw "Certificate file not found: $CertificateFile" }
        $cert = Get-Content -Raw -Path $CertificateFile
    }

    $body = [ordered]@{
        server   = $VCenterServer
        user     = $VCenterCredential.UserName
        password = $VCenterCredential.GetNetworkCredential().Password
    }
    if ($cert) { $body.certificate = $cert }
    $json = $body | ConvertTo-Json -Depth 5
    $redactedJson = (Copy-RedactedHashtable -Source $body -RedactKeys 'password') | ConvertTo-Json -Depth 5

    Invoke-SspiApi -Connection $Connection -Method POST -Path '/providers' `
        -BodyJson $json -RedactedBodyJson $redactedJson -Troubleshoot:$Troubleshoot
}

Function Get-SspInstallerVCenterServer {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns vCenter Server(s) registered with the SSP Installer
        .DESCRIPTION
            This cmdlet returns either all vCenter Server providers registered
            with SSPI, or a single one when -ProviderId is specified.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER ProviderId
            The ID of a specific vCenter Server provider to return. Returns all
            providers if omitted.
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Get-SspInstallerVCenterServer

        .EXAMPLE
            Get-SspInstallerVCenterServer -ProviderId dcd85e06-49f1-42d9-8241-ec754439c9be
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [string]$ProviderId,
        [switch]$Troubleshoot
    )
    $path = if ($ProviderId) { "/providers/$ProviderId" } else { '/providers' }
    Out-SspiResult (Invoke-SspiApi -Connection $Connection -Method GET -Path $path -Troubleshoot:$Troubleshoot)
}

Function Remove-SspInstallerVCenterServer {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Removes a vCenter Server registered with the SSP Installer
        .DESCRIPTION
            This cmdlet deletes (DELETEs) a vCenter Server provider from SSPI.
            This is a destructive operation and executes immediately.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER VCenterId
            The ID of the vCenter Server provider to remove (see
            Get-SspInstallerVCenterServer)
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Remove-SspInstallerVCenterServer -VCenterId dcd85e06-49f1-42d9-8241-ec754439c9be
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$VCenterId,
        [switch]$Troubleshoot
    )
    Invoke-SspiApi -Connection $Connection -Method DELETE -Path "/providers/$VCenterId" -Troubleshoot:$Troubleshoot
    Write-Host "vCenter Server '$VCenterId' successfully removed."
}

# ---------------------------------------------------------------------------
# SSP bundle upload: POST /sspi/bundles/local, GET/DELETE /sspi/bundles(/{id})
# x-large-file-upload: true in the spec -> stream from disk, don't buffer.
# Uses HttpClient directly (not Invoke-SspiApi) so it has its own
# Troubleshoot handling.
# ---------------------------------------------------------------------------

Function New-SspInstallerPackage {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Uploads an SSP bundle (.tar) to the SSP Installer's package depot
        .DESCRIPTION
            This cmdlet streams a bundle file from disk (rather than buffering it
            in memory, since bundles can be multi-GB) to SSPI's package depot,
            showing a progress bar as it uploads. Upload is asynchronous on the
            server side — pass -PollStatus to wait and watch it move out of
            IN_PROGRESS.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER FilePath
            Path to the .tar bundle file to upload
        .PARAMETER BundleType
            PLATFORM (default) | INSTALLER | PLATFORM_PATCH | AVI_OPERATIONS |
            AVI_OPERATIONS_PATCH | BMS | SVM
        .PARAMETER PollStatus
            After a successful upload, poll the bundle's status every 5 seconds
            until it leaves IN_PROGRESS (READY / FAILED / ERROR)
        .PARAMETER Troubleshoot
            Print the HTTP method, URI, and upload details, without affecting
            the actual request.

        .EXAMPLE
            New-SspInstallerPackage -FilePath ~/Desktop/ssp-platform-5.2.0.tar -PollStatus
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$FilePath,
        [ValidateSet('PLATFORM', 'INSTALLER', 'PLATFORM_PATCH', 'AVI_OPERATIONS', 'AVI_OPERATIONS_PATCH', 'BMS', 'SVM')]
        [string]$BundleType = 'PLATFORM',
        [switch]$PollStatus,
        [switch]$Troubleshoot
    )
    Assert-SspiConnection $Connection
    $resolved = Resolve-Path -Path $FilePath -ErrorAction Stop
    $fileInfo = Get-Item -Path $resolved
    $uri = "$($Connection.BaseUrl)/bundles/local?type=$BundleType"

    if ($Troubleshoot) {
        Write-Host "[TROUBLESHOOT] POST $uri"
        Write-Host ("Body: multipart/form-data; file={0} ({1:N2} MB)" -f $fileInfo.Name, ($fileInfo.Length / 1MB))
    }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    if ($Connection.Insecure) {
        # NOT a PowerShell scriptblock: { $true } gets invoked by .NET on the TLS
        # negotiation thread, which has no PowerShell runspace attached and fails
        # with "There is no Runspace available to run scripts in this thread."
        # This is .NET's own built-in bypass delegate — a real compiled delegate,
        # so it has no runspace dependency.
        $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    }
    # Explicitly enable Tls12/Tls13 rather than relying on the OS/.NET default —
    # a common cause of "SSL connection could not be established" against
    # self-signed lab appliances on a custom HttpClientHandler (this exact
    # symptom, on this exact code path — Invoke-RestMethod elsewhere in this
    # script uses a different internal handler and isn't affected).
    try {
        $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
    }
    catch {
        $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
    }
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [System.TimeSpan]::FromHours(4)
    $pair = "{0}:{1}" -f $Connection.Credential.UserName, $Connection.Credential.GetNetworkCredential().Password
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new(
        'Basic', [Convert]::ToBase64String($bytes))

    Add-SspiProgressStreamType
    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($fileInfo.FullName)
        $progressStream = [SspiProgressStream]::new($stream)
        $streamContent = [System.Net.Http.StreamContent]::new($progressStream)
        $streamContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
        $multipart = [System.Net.Http.MultipartFormDataContent]::new()
        $multipart.Add($streamContent, 'file', $fileInfo.Name)

        $activity = "Uploading $($fileInfo.Name)"
        $totalBytes = $fileInfo.Length
        try {
            $postTask = $client.PostAsync($uri, $multipart)
            $barWidth = 30
            while (-not $postTask.IsCompleted) {
                Start-Sleep -Milliseconds 500
                $sent = $progressStream.TotalBytesRead
                $pct = if ($totalBytes -gt 0) { [Math]::Min(100, [Math]::Round(($sent / $totalBytes) * 100, 1)) } else { 0 }
                $filled = [Math]::Floor(($pct / 100) * $barWidth)
                $bar = ('#' * $filled).PadRight($barWidth, '-')
                $statusText = "[{0}] {1}% ({2:N1} MB / {3:N1} MB)" -f $bar, $pct, ($sent / 1MB), ($totalBytes / 1MB)
                # A single in-place widget (Write-Progress), not scrolling text — this
                # host doesn't render its own fill bar for the status text, so we build
                # one manually here.
                Write-Progress -Activity $activity -Status $statusText -PercentComplete $pct
            }
            Write-Progress -Activity $activity -Completed
            $response = $postTask.GetAwaiter().GetResult()
        }
        catch {
            Write-Progress -Activity $activity -Completed
            # Unwrap the full InnerException chain — .NET's outer message for any TLS
            # failure is the same generic "SSL connection could not be established",
            # the actual reason (expired cert, name mismatch, protocol mismatch, etc.)
            # is buried in .InnerException and gets silently dropped otherwise.
            $chain = @()
            $ex = $_.Exception
            while ($ex) { $chain += $ex.Message; $ex = $ex.InnerException }
            throw [System.Exception]::new("Upload connection to $uri failed: " + ($chain -join ' -> '), $_.Exception)
        }
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "Upload failed: HTTP $([int]$response.StatusCode) $($response.ReasonPhrase) - $body"
        }
        $result = $body | ConvertFrom-Json

        if ($PollStatus -and $result.id) {
            do {
                Start-Sleep -Seconds 5
                $bundle = Invoke-SspiApi -Connection $Connection -Method GET -Path "/bundles/$($result.id)" -Troubleshoot:$Troubleshoot
                Write-Host ("Status: {0}  Progress: {1}%  {2}" -f $bundle.status, $bundle.progress, $bundle.message)
            } while ($bundle.status -eq 'IN_PROGRESS')
            return $bundle
        }
        return $result
    }
    finally {
        if ($stream) { $stream.Dispose() }
        $client.Dispose()
    }
}

Function Get-SspInstallerPackage {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns SSP bundle(s) uploaded to the SSP Installer's package depot
        .DESCRIPTION
            This cmdlet returns either all bundles in SSPI's package depot, or a
            single one when -BundleId is specified.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER BundleId
            The ID of a specific bundle to return. Returns all bundles if
            omitted.
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Get-SspInstallerPackage

        .EXAMPLE
            Get-SspInstallerPackage -BundleId dcd85e06-49f1-42d9-8241-ec754439c9be
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [string]$BundleId,
        [switch]$Troubleshoot
    )
    $path = if ($BundleId) { "/bundles/$BundleId" } else { '/bundles' }
    Out-SspiResult (Invoke-SspiApi -Connection $Connection -Method GET -Path $path -Troubleshoot:$Troubleshoot)
}

Function Remove-SspInstallerPackage {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Removes an SSP bundle from the SSP Installer's package depot
        .DESCRIPTION
            This cmdlet deletes (DELETEs) a bundle from SSPI's package depot.
            This is a destructive operation and executes immediately.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER BundleId
            The ID of the bundle to remove (see Get-SspInstallerPackage)
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Remove-SspInstallerPackage -BundleId dcd85e06-49f1-42d9-8241-ec754439c9be
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$BundleId,
        [switch]$Troubleshoot
    )
    Invoke-SspiApi -Connection $Connection -Method DELETE -Path "/bundles/$BundleId" -Troubleshoot:$Troubleshoot
    Write-Host "Bundle '$BundleId' successfully removed."
}

# ---------------------------------------------------------------------------
# vCenter friendly-name -> MoRef resolution (requires VMware.PowerCLI)
# Only invoked if a *Name parameter is supplied without its *Id counterpart.
# ---------------------------------------------------------------------------

Function Resolve-SspVCenterMoRefs {
    param(
        [string]$VCenterServer,
        [PSCredential]$VCenterCredential,
        [string]$DatacenterName, [string]$ClusterName, [string]$DatastoreName,
        [string]$StoragePolicyName, [string]$ResourcePoolName,
        [string]$NetworkName, [string]$PortgroupName
    )

    if (-not (Get-Module -Name VMware.VimAutomation.Core -ListAvailable)) {
        throw "Resolving vSphere names to MoRef IDs requires the VMware.PowerCLI module (VMware.VimAutomation.Core). " +
              "Install it (Install-Module VMware.PowerCLI -Scope CurrentUser), or pass the *Id parameters directly instead of *Name."
    }
    Import-Module VMware.VimAutomation.Core -ErrorAction Stop | Out-Null

    $connectedHere = $false
    if (-not $global:DefaultVIServers -or $global:DefaultVIServers.Count -eq 0) {
        if (-not $VCenterServer) { throw "-VCenterServer is required to resolve names to MoRef IDs (no existing PowerCLI connection found)." }
        if (-not $VCenterCredential) { $VCenterCredential = Get-Credential -Message "vCenter credentials for $VCenterServer" }
        Connect-VIServer -Server $VCenterServer -Credential $VCenterCredential -Force -ErrorAction Stop | Out-Null
        $connectedHere = $true
    }

    try {
        $result = [ordered]@{}
        $dcObj = $null
        $clusterObj = $null

        if ($DatacenterName) {
            $dcObj = Get-Datacenter -Name $DatacenterName -ErrorAction Stop
            $result.DatacenterId = $dcObj.ExtensionData.MoRef.Value
        }
        if ($ClusterName) {
            $clusterParams = @{ Name = $ClusterName }
            if ($dcObj) { $clusterParams.Location = $dcObj }
            $clusterObj = Get-Cluster @clusterParams -ErrorAction Stop
            $result.ClusterId = $clusterObj.ExtensionData.MoRef.Value
        }
        if ($DatastoreName) {
            # Get-Datastore -Location only accepts Datacenter, Folder, or DatastoreCluster
            # objects — NOT Cluster, unlike Get-Cluster/Get-ResourcePool/Get-Datastore's
            # own siblings. Scope to the datacenter only.
            $dsParams = @{ Name = $DatastoreName }
            if ($dcObj) { $dsParams.Location = $dcObj }
            $dsObj = Get-Datastore @dsParams -ErrorAction Stop
            $result.DatastoreId = $dsObj.ExtensionData.MoRef.Value
        }
        if ($ResourcePoolName) {
            $rpParams = @{ Name = $ResourcePoolName }
            if ($clusterObj) { $rpParams.Location = $clusterObj }
            $rpObj = Get-ResourcePool @rpParams -ErrorAction Stop
            $result.ResourcePoolId = $rpObj.ExtensionData.MoRef.Value
        }
        if ($StoragePolicyName) {
            if (-not (Get-Module -Name VMware.VimAutomation.Storage -ListAvailable)) {
                throw "Resolving -StoragePolicyName requires the VMware.VimAutomation.Storage module (part of VMware.PowerCLI)."
            }
            Import-Module VMware.VimAutomation.Storage -ErrorAction Stop | Out-Null
            $policyObj = Get-SpbmStoragePolicy -Name $StoragePolicyName -ErrorAction Stop
            $result.StoragePolicyId = $policyObj.Id
        }
        if ($PortgroupName) {
            $pgObj = Get-VDPortgroup -Name $PortgroupName -ErrorAction Stop
            $result.PortgroupId = $pgObj.ExtensionData.MoRef.Value
            # network_id (the parent DVS) is a separate required field from
            # portgroup_id in the API, but a portgroup name already implies
            # which switch it lives on — derive it here so callers don't have
            # to separately pass -NetworkName just to name the obvious parent.
            # An explicit -NetworkName below still overrides this if given.
            if ($pgObj.VDSwitch) { $result.NetworkId = $pgObj.VDSwitch.ExtensionData.MoRef.Value }
        }
        if ($NetworkName) {
            $vdsObj = Get-VDSwitch -Name $NetworkName -ErrorAction Stop
            $result.NetworkId = $vdsObj.ExtensionData.MoRef.Value
        }
        return [PSCustomObject]$result
    }
    finally {
        if ($connectedHere) { Disconnect-VIServer -Server $VCenterServer -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Deployment: POST/GET/DELETE /sspi/platforms  (CreatePlatform / PlatformFullConfig)
# ---------------------------------------------------------------------------

Function New-SspInstallerDeployment {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Deploys (or drives the lifecycle of) an SSP platform via the SSP Installer
        .DESCRIPTION
            This cmdlet POSTs a CreatePlatform request to SSPI, describing the
            compute, network, and service configuration for an SSP platform
            deployment against a registered vCenter Server. Compute/network
            objects can be identified either by their vSphere MoRef/UUID (*Id
            params) or by friendly name (*Name params, which requires
            VMware.PowerCLI and -VCenterServer/-VCenterCredential to resolve).
            -Operation controls where the deployment lifecycle goes next
            (precheck, start, continue, retry, etc.).
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER VCenterId
            The ID of the vCenter Server provider to deploy to (see
            Get-SspInstallerVCenterServer)
        .PARAMETER Operation
            The desired lifecycle state to move the deployment to:
            PRECHECK_ONLY (default) | RESET_PRECHECK | CONTINUE | START | STOP |
            RETRY | CLEAN
        .PARAMETER DatacenterName
            Friendly name of the vSphere datacenter. Resolved to -DatacenterId
            via PowerCLI; use -DatacenterId directly to skip resolution.
        .PARAMETER DatacenterId
            MoRef ID of the vSphere datacenter
        .PARAMETER ClusterName
            Friendly name of the vSphere cluster. Resolved to -ClusterId via
            PowerCLI; use -ClusterId directly to skip resolution.
        .PARAMETER ClusterId
            MoRef ID of the vSphere cluster
        .PARAMETER DatastoreName
            Friendly name of the content datastore. Resolved to -DatastoreId
            via PowerCLI; use -DatastoreId directly to skip resolution.
        .PARAMETER DatastoreId
            MoRef ID of the content datastore
        .PARAMETER StoragePolicyName
            Friendly name of the storage policy. Resolved to -StoragePolicyId
            via PowerCLI (requires VMware.VimAutomation.Storage); use
            -StoragePolicyId directly to skip resolution.
        .PARAMETER StoragePolicyId
            ID of the storage policy
        .PARAMETER ResourcePoolName
            Friendly name of the resource pool. Resolved to -ResourcePoolId via
            PowerCLI; use -ResourcePoolId directly to skip resolution.
        .PARAMETER ResourcePoolId
            MoRef ID of the resource pool
        .PARAMETER EnableResourceReservation
            Whether to reserve compute resources for the deployment. Defaults to
            $true.
        .PARAMETER VCenterServer
            Hostname/FQDN of the vCenter Server to connect to via PowerCLI, only
            used to resolve any *Name parameters above. Not needed if you're
            already connected via PowerCLI, or if you only pass *Id parameters.
        .PARAMETER VCenterCredential
            Credential for -VCenterServer. Prompted for if omitted and needed.
        .PARAMETER Dns
            One or more DNS server IP addresses
        .PARAMETER Ntp
            NTP server hostname/IP
        .PARAMETER SearchDomain
            DNS search domain
        .PARAMETER NetworkName
            Friendly name of the distributed virtual switch. Resolved to
            -NetworkId via PowerCLI; use -NetworkId directly to skip resolution.
        .PARAMETER NetworkId
            MoRef ID of the distributed virtual switch
        .PARAMETER PortgroupName
            Friendly name of the portgroup. Resolved to -PortgroupId (and, if
            -NetworkId/-NetworkName isn't given, its parent switch) via
            PowerCLI; use -PortgroupId directly to skip resolution.
        .PARAMETER PortgroupId
            MoRef ID of the portgroup
        .PARAMETER PlatformSubnet
            Subnet (CIDR) for the platform network
        .PARAMETER PlatformDefaultGateway
            Default gateway IP for the platform network
        .PARAMETER NodePool
            One or more node IP pools, each formatted as "START-END" or
            "START-END:NAME"
        .PARAMETER ServicePool
            One or more service IP pools, each formatted as "START-END" or
            "START-END:NAME"
        .PARAMETER InstanceFqdn
            Ingress FQDN for the SSP platform instance
        .PARAMETER MessagingFqdn
            Kafka/messaging FQDN for the SSP platform instance
        .PARAMETER SspBundleId
            The ID of the uploaded SSP bundle to deploy (see
            Get-SspInstallerPackage). Its add-ons are used automatically unless
            -AddOnIds is passed explicitly.
        .PARAMETER InstanceName
            Friendly name for the SSP platform instance
        .PARAMETER AdminPassword
            Admin password for the deployed platform
        .PARAMETER AuditPassword
            Audit user password for the deployed platform
        .PARAMETER AddOnIds
            One or more add-on IDs to include. Defaults to every add-on carried
            by -SspBundleId; pass this to override that.
        .PARAMETER PreserveAddons
            Whether to preserve existing add-ons across an update
        .PARAMETER SspType
            ATP (default) | AVI_OPERATIONS
        .PARAMETER FormFactor
            SMALL | MEDIUM | LARGE | EXTRA_LARGE
        .PARAMETER ControllerCount
            Number of controller nodes. Defaults to 3 — LARGE/MEDIUM/EXTRA_LARGE
            form factors require exactly 3; AVI_OPERATIONS uses 1 instead.
        .PARAMETER WorkerCount
            Number of worker nodes
        .PARAMETER Troubleshoot
            Print the HTTP method, URI, and request body (with secrets redacted)
            sent to the API, without affecting the actual request.

        .EXAMPLE
            New-SspInstallerDeployment -VCenterId dcd85e06-49f1-42d9-8241-ec754439c9be `
                -SspBundleId a1b2c3d4-... -InstanceName ssp01 `
                -DatacenterName DC01 -ClusterName Cluster01 -DatastoreName vsanDatastore `
                -Dns 10.0.0.10 -Ntp ntp.vcf.lab -SearchDomain vcf.lab `
                -NetworkName VDS01 -PortgroupName SSP-Mgmt `
                -PlatformSubnet 10.0.1.0/24 -PlatformDefaultGateway 10.0.1.1 `
                -NodePool 10.0.1.10-10.0.1.20 -ServicePool 10.0.1.21-10.0.1.30 `
                -InstanceFqdn ssp01.vcf.lab -MessagingFqdn ssp01-msg.vcf.lab
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$VCenterId,

        [ValidateSet('PRECHECK_ONLY', 'RESET_PRECHECK', 'CONTINUE', 'START', 'STOP', 'RETRY', 'CLEAN')]
        [string]$Operation = 'PRECHECK_ONLY',

        # --- compute: friendly name OR direct MoRef/UUID id ---
        [string]$DatacenterName, [string]$DatacenterId,
        [string]$ClusterName, [string]$ClusterId,
        [string]$DatastoreName, [string]$DatastoreId,
        [string]$StoragePolicyName, [string]$StoragePolicyId,
        [string]$ResourcePoolName, [string]$ResourcePoolId,
        [bool]$EnableResourceReservation = $true,

        # vCenter connection used only for *Name resolution above
        [string]$VCenterServer,
        [PSCredential]$VCenterCredential,

        # --- network ---
        [Parameter(Mandatory)][string[]]$Dns,
        [Parameter(Mandatory)][string]$Ntp,
        [Parameter(Mandatory)][string]$SearchDomain,
        [string]$NetworkName, [string]$NetworkId,
        [string]$PortgroupName, [string]$PortgroupId,
        [Parameter(Mandatory)][string]$PlatformSubnet,
        [Parameter(Mandatory)][string]$PlatformDefaultGateway,
        [Parameter(Mandatory)][string[]]$NodePool,
        [Parameter(Mandatory)][string[]]$ServicePool,

        # --- service ---
        [Parameter(Mandatory)][string]$InstanceFqdn,
        [Parameter(Mandatory)][string]$MessagingFqdn,
        [Parameter(Mandatory)][string]$SspBundleId,
        [Parameter(Mandatory)][string]$InstanceName,
        [string]$AdminPassword,
        [string]$AuditPassword,
        [string[]]$AddOnIds,
        [bool]$PreserveAddons,

        # --- system ---
        [ValidateSet('ATP', 'AVI_OPERATIONS')][string]$SspType = 'ATP',
        [ValidateSet('SMALL', 'MEDIUM', 'LARGE', 'EXTRA_LARGE')][string]$FormFactor,
        # LARGE/MEDIUM/EXTRA_LARGE form factors require exactly 3 (min=max=3 per the API).
        # Only AVI_OPERATIONS uses 1 instead — override explicitly if you're on that SspType.
        [int]$ControllerCount = 3,
        [int]$WorkerCount,

        [switch]$Troubleshoot
    )
    Assert-SspiConnection $Connection

    # A bundle carries its own add-ons (Bundle.addons[] — see GET /bundles/{id}); unless the
    # caller explicitly overrides with -AddOnIds, pull all of them automatically so that's one
    # less thing to look up by hand.
    if (-not $PSBoundParameters.ContainsKey('AddOnIds')) {
        $bundle = Invoke-SspiApi -Connection $Connection -Method GET -Path "/bundles/$SspBundleId" -Troubleshoot:$Troubleshoot
        if ($bundle -and $bundle.addons) {
            $AddOnIds = @($bundle.addons | ForEach-Object { $_.id })
        }
    }

    # Resolve any friendly names to MoRef/UUID IDs (skips entirely if only *Id params were given).
    $needsResolution = $DatacenterName -or $ClusterName -or $DatastoreName -or $StoragePolicyName -or
                        $ResourcePoolName -or $NetworkName -or $PortgroupName
    if ($needsResolution) {
        $resolved = Resolve-SspVCenterMoRefs -VCenterServer $VCenterServer -VCenterCredential $VCenterCredential `
            -DatacenterName $DatacenterName -ClusterName $ClusterName -DatastoreName $DatastoreName `
            -StoragePolicyName $StoragePolicyName -ResourcePoolName $ResourcePoolName `
            -NetworkName $NetworkName -PortgroupName $PortgroupName

        if ($resolved.DatacenterId) { $DatacenterId = $resolved.DatacenterId }
        if ($resolved.ClusterId) { $ClusterId = $resolved.ClusterId }
        if ($resolved.DatastoreId) { $DatastoreId = $resolved.DatastoreId }
        if ($resolved.StoragePolicyId) { $StoragePolicyId = $resolved.StoragePolicyId }
        if ($resolved.ResourcePoolId) { $ResourcePoolId = $resolved.ResourcePoolId }
        if ($resolved.NetworkId) { $NetworkId = $resolved.NetworkId }
        if ($resolved.PortgroupId) { $PortgroupId = $resolved.PortgroupId }
    }

    foreach ($pair in @(
            @{ Name = 'DatacenterId'; Value = $DatacenterId }
            @{ Name = 'ClusterId'; Value = $ClusterId }
            @{ Name = 'DatastoreId'; Value = $DatastoreId }
            @{ Name = 'StoragePolicyId'; Value = $StoragePolicyId }
            @{ Name = 'NetworkId'; Value = $NetworkId }
            @{ Name = 'PortgroupId'; Value = $PortgroupId }
        )) {
        if (-not $pair.Value) {
            throw "$($pair.Name) could not be determined — pass it directly, or pass the matching *Name plus -VCenterServer/-VCenterCredential to resolve it."
        }
    }

    $compute = [ordered]@{
        datacenter_id                = $DatacenterId
        cluster_id                   = $ClusterId
        storage_policy_id            = $StoragePolicyId
        content_datastore_id         = $DatastoreId
        enable_resource_reservation  = $EnableResourceReservation
    }
    if ($ResourcePoolId) { $compute.resource_pool_id = $ResourcePoolId }

    $networkConfig = [ordered]@{
        network_id               = $NetworkId
        portgroup_id              = $PortgroupId
        platform_subnet           = $PlatformSubnet
        platform_default_gateway  = $PlatformDefaultGateway
        node_pools                = @($NodePool | ForEach-Object { ConvertTo-PoolObject -Value $_ -FlagName '-NodePool' })
        service_pools             = @($ServicePool | ForEach-Object { ConvertTo-PoolObject -Value $_ -FlagName '-ServicePool' })
    }
    $network = [ordered]@{
        dns             = @($Dns)
        ntp             = $Ntp
        search_domain   = $SearchDomain
        network_configs = @($networkConfig)
    }

    $service = [ordered]@{
        ingress_fqdn   = $InstanceFqdn
        kafka_fqdn     = $MessagingFqdn
        ssp_bundle_id  = $SspBundleId
        instance_name  = $InstanceName
    }
    if ($AdminPassword -or $AuditPassword) {
        $service.password_configuration = [ordered]@{ admin_password = $AdminPassword; audit_password = $AuditPassword }
    }
    if ($AddOnIds) { $service.addon_ids = @($AddOnIds) }
    if ($PSBoundParameters.ContainsKey('PreserveAddons')) { $service.preserve_addons = $PreserveAddons }

    $system = [ordered]@{ ssp_type = $SspType }
    if ($FormFactor) { $system.form_factor = $FormFactor }
    $system.controller_count = $ControllerCount
    if ($PSBoundParameters.ContainsKey('WorkerCount')) { $system.worker_count = $WorkerCount }

    $payload = [ordered]@{
        desired_state = $Operation
        provider_id   = $VCenterId
        compute       = $compute
        network       = $network
        service       = $service
        system        = $system
    }
    $json = $payload | ConvertTo-Json -Depth 12

    $redactedService = Copy-RedactedHashtable -Source $service -RedactKeys @()
    if ($redactedService.Contains('password_configuration')) {
        $redactedService.password_configuration = Copy-RedactedHashtable -Source $service.password_configuration -RedactKeys @('admin_password', 'audit_password')
    }
    $redactedPayload = [ordered]@{
        desired_state = $Operation; provider_id = $VCenterId
        compute = $compute; network = $network; service = $redactedService; system = $system
    }
    $redactedJson = $redactedPayload | ConvertTo-Json -Depth 12

    Invoke-SspiApi -Connection $Connection -Method POST -Path '/platforms' `
        -BodyJson $json -RedactedBodyJson $redactedJson -Troubleshoot:$Troubleshoot
}

Function Get-SspInstallerDeployment {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns SSP platform deployment(s) from the SSP Installer
        .DESCRIPTION
            This cmdlet returns either all platform deployments known to SSPI,
            or a single one when -PlatformId is specified.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER PlatformId
            The ID of a specific platform deployment to return. Returns all
            deployments if omitted.
        .PARAMETER Status
            Return only the deployment's status (requires -PlatformId)
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Get-SspInstallerDeployment

        .EXAMPLE
            Get-SspInstallerDeployment -PlatformId dcd85e06-49f1-42d9-8241-ec754439c9be -Status
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [string]$PlatformId,
        [switch]$Status,
        [switch]$Troubleshoot
    )
    $path = if ($PlatformId -and $Status) { "/platforms/$PlatformId/status" }
            elseif ($PlatformId) { "/platforms/$PlatformId" }
            else { '/platforms' }
    Out-SspiResult (Invoke-SspiApi -Connection $Connection -Method GET -Path $path -Troubleshoot:$Troubleshoot)
}

Function Remove-SspInstallerDeployment {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Removes an SSP platform deployment from the SSP Installer
        .DESCRIPTION
            This cmdlet deletes (DELETEs) a platform deployment from SSPI. This
            is a destructive operation and executes immediately.
        .PARAMETER Connection
            The SSPI connection object returned by Connect-SspInstaller. Defaults
            to the session's connection, so you don't need to pass this.
        .PARAMETER PlatformId
            The ID of the platform deployment to remove (see
            Get-SspInstallerDeployment)
        .PARAMETER Force
            Force the deletion even if the platform is not in a normally
            deletable state
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Remove-SspInstallerDeployment -PlatformId dcd85e06-49f1-42d9-8241-ec754439c9be

        .EXAMPLE
            Remove-SspInstallerDeployment -PlatformId dcd85e06-49f1-42d9-8241-ec754439c9be -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspiConnection,
        [Parameter(Mandatory)][string]$PlatformId,
        [switch]$Force,
        [switch]$Troubleshoot
    )
    $path = "/platforms/$PlatformId"
    if ($Force) { $path += "?action=force_delete" }
    Invoke-SspiApi -Connection $Connection -Method DELETE -Path $path -Troubleshoot:$Troubleshoot
    Write-Host "Deployment '$PlatformId' successfully removed."
}

# ---------------------------------------------------------------------------
# SSP Instance (the deployed platform itself, NOT the SSP Installer): NSX
# Manager onboarding via GET/POST/DELETE /ssp/sites
#
# This is a second, separate connection type from Connect-SspInstaller above —
# SSPI deploys the platform, this talks to the platform's own site-service
# once it's up. Source of truth: common/api/site-service/public_specs/sites.yaml
# and site_schemas.yaml (NsxManagerSite / SiteConnectionInfo).
# Base URL: https://<host>/ssp
# ---------------------------------------------------------------------------

Function Assert-SspInstanceConnection {
    param($Connection)
    if (-not $Connection) {
        throw "No SSP instance connection available. Run Connect-SspInstance first (it sets the default connection automatically), or pass -Connection explicitly."
    }
    if ($Connection.PSTypeNames -notcontains 'Ssp.InstanceConnection') {
        throw "Expected a connection object from Connect-SspInstance."
    }
}

Function Invoke-SspInstanceApi {
    <#
    Single choke point for every SSP instance (site-service) call. Mirrors
    Invoke-SspiApi's -Troubleshoot printing so individual Get/New/Remove
    functions don't have to duplicate it.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [string]$BodyJson,
        [string]$RedactedBodyJson,
        [switch]$Troubleshoot
    )
    Assert-SspInstanceConnection $Connection
    $uri = "$($Connection.BaseUrl)$Path"

    if ($Troubleshoot) {
        Write-Host "[TROUBLESHOOT] $Method $uri"
        $display = if ($RedactedBodyJson) { $RedactedBodyJson } else { $BodyJson }
        if ($display) { Write-Host $display }
    }

    $headers = Get-SspiAuthHeader -Credential $Connection.Credential
    $timeoutSec = if ($Connection.TimeoutSec) { $Connection.TimeoutSec } else { 15 }
    $params = @{ Method = $Method; Uri = $uri; Headers = $headers; TimeoutSec = $timeoutSec }
    if ($BodyJson) { $params.Body = $BodyJson; $params.ContentType = 'application/json' }

    if ($Connection.Insecure) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { Enable-SspiInsecureTls }
    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            throw [System.Exception]::new(
                "Authentication failed (HTTP $statusCode) calling $Method $uri. Please re-authenticate using Connect-SspInstance — your session/credentials are no longer valid.",
                $_.Exception)
        }

        $message = $_.ErrorDetails.Message
        if (-not $message -and $_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $message = $reader.ReadToEnd()
            }
            catch { }
        }
        if (-not $message) { $message = $_.Exception.Message }
        throw [System.Exception]::new("SSP instance API error ($Method $uri): $message", $_.Exception)
    }
}

Function Connect-SspInstance {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Connect to a deployed SSP Instance (the platform itself, not the SSP Installer)
        .DESCRIPTION
            Creates a connection object (host + credential) and sets it as the
            default for every other SSP instance function in this session
            (Get-/New-/Remove-SspInstanceNsx). There is no server-side session
            here — this just packages what every other call needs and stashes
            it so you don't have to pass -Connection every time. This is a
            separate connection from Connect-SspInstaller: that one talks to
            the installer (SSPI); this one talks to the deployed platform's
            own API once it's up and running.
        .PARAMETER SspInstanceHost
            The hostname/FQDN or IP address of the deployed SSP Instance
        .PARAMETER Credential
            Credential for the SSP Instance API (Basic auth). Prompted for if
            omitted. Defaults to username 'admin'.
        .PARAMETER Insecure
            Skip TLS certificate validation. Defaults to $true, matching a lab
            environment with self-signed certificates.
        .PARAMETER TimeoutSec
            Request timeout in seconds. Defaults to 15.

        .EXAMPLE
            Connect-SspInstance -SspInstanceHost ssp-inst01.vcf.lab
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SspInstanceHost,
        [PSCredential]$Credential,
        [bool]$Insecure = $true,
        [int]$TimeoutSec = 15
    )
    if (-not $Credential) {
        $Credential = Get-Credential -Message "SSP instance credentials for https://$SspInstanceHost/ssp" -UserName 'admin'
    }
    $conn = [PSCustomObject]@{
        PSTypeName      = 'Ssp.InstanceConnection'
        SspInstanceHost = $SspInstanceHost
        BaseUrl         = "https://$SspInstanceHost/ssp"
        Credential      = $Credential
        Insecure        = $Insecure
        TimeoutSec      = $TimeoutSec
    }
    $script:SspInstanceConnection = $conn
    Write-Host "Default SSP instance connection set: $($conn.BaseUrl) (user: $($Credential.UserName)). Pass -Connection to override for a specific call."
    return $conn
}

Function Get-SspInstanceNsx {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns NSX Manager(s) onboarded to a deployed SSP Instance
        .DESCRIPTION
            This cmdlet returns either all NSX Manager sites onboarded to the
            SSP Instance (GET /ssp/sites?site_type=NSX_MANAGER), or a single
            one when -NsxManagerId is specified. Note the platform never
            stores the username/password used to onboard a site, so those
            fields always come back empty.
        .PARAMETER Connection
            The SSP instance connection object returned by Connect-SspInstance.
            Defaults to the session's connection, so you don't need to pass this.
        .PARAMETER NsxManagerId
            The site ID of a specific NSX Manager to return. Returns all
            onboarded NSX Managers if omitted.
        .PARAMETER Troubleshoot
            Print the HTTP method and URI sent to the API, without affecting the
            actual request.

        .EXAMPLE
            Get-SspInstanceNsx

        .EXAMPLE
            Get-SspInstanceNsx -NsxManagerId 2dc09816-34c0-43fb-99a6-b19b249a43da
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspInstanceConnection,
        [string]$NsxManagerId,
        [switch]$Troubleshoot
    )
    $path = if ($NsxManagerId) { "/sites/$NsxManagerId" } else { '/sites?site_type=NSX_MANAGER' }
    Out-SspiResult (Invoke-SspInstanceApi -Connection $Connection -Method GET -Path $path -Troubleshoot:$Troubleshoot)
}

Function New-SspInstanceNsx {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Onboards a new NSX Manager to a deployed SSP Instance
        .DESCRIPTION
            This cmdlet POSTs a new NSX_MANAGER site to the SSP Instance's
            site-service (POST /ssp/sites) with a DYNAMIC connection (SSP
            discovers all manager IPs in the cluster from the hostname given).
            Onboarding runs asynchronously on the platform side: prechecks
            first, then the actual onboarding. Pass -PollStatus to wait and
            watch it move out of ONBOARD_IN_PROGRESS. The username/password
            given here are one-time use to establish the connection — SSP does
            not store or re-use them.
        .PARAMETER Connection
            The SSP instance connection object returned by Connect-SspInstance.
            Defaults to the session's connection, so you don't need to pass this.
        .PARAMETER NsxManager
            The hostname/FQDN of the NSX Manager to onboard. SSP does not
            support connecting via IP for this call.
        .PARAMETER NsxCredential
            Credential for the NSX Manager (one-time use to establish the
            connection). Prompted for if omitted.
        .PARAMETER CertificateFile
            Path to a PEM-encoded certificate file used to authenticate with
            the NSX Manager.
        .PARAMETER SiteName
            Friendly name for the site. Not editable after onboarding.
            Defaults to -NsxManager if omitted.
        .PARAMETER Force
            Use if the NSX Manager was previously onboarded to a different SSP
            instance and stale references remain on it (SiteRegistrationPrecheck
            failing). Deletes those stale artifacts and onboards to this
            instance instead. This does NOT replace properly offboarding the
            manager from its old SSP instance first — use with care.
        .PARAMETER PollStatus
            After a successful onboard request, poll the site's status every
            5 seconds until it leaves ONBOARD_IN_PROGRESS.
        .PARAMETER Troubleshoot
            Print the HTTP method, URI, and request body (with secrets
            redacted) sent to the API, without affecting the actual request.

        .EXAMPLE
            New-SspInstanceNsx -NsxManager nsx01.vcf.lab -NsxCredential $nsxCred -CertificateFile ~/Desktop/nsx01.vcf.lab.pem -PollStatus
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspInstanceConnection,
        [Parameter(Mandatory)][string]$NsxManager,
        [PSCredential]$NsxCredential,
        [Parameter(Mandatory)][string]$CertificateFile,
        [string]$SiteName,
        [switch]$Force,
        [switch]$PollStatus,
        [switch]$Troubleshoot
    )
    Assert-SspInstanceConnection $Connection
    if (-not $NsxCredential) {
        $NsxCredential = Get-Credential -Message "NSX Manager credentials for $NsxManager"
    }
    if (-not (Test-Path $CertificateFile)) { throw "Certificate file not found: $CertificateFile" }
    $cert = Get-Content -Raw -Path $CertificateFile
    if (-not $SiteName) { $SiteName = $NsxManager }

    $body = [ordered]@{
        site_type            = 'NSX_MANAGER'
        site_name            = $SiteName
        desired_state        = 'ONBOARD'
        site_connection_info = [ordered]@{
            connection_type = 'DYNAMIC'
            hostname        = $NsxManager
            username        = $NsxCredential.UserName
            password        = $NsxCredential.GetNetworkCredential().Password
            certificate     = $cert
        }
    }
    $json = $body | ConvertTo-Json -Depth 6

    $redactedConnInfo = Copy-RedactedHashtable -Source $body.site_connection_info -RedactKeys @('password', 'certificate')
    $redactedBody = [ordered]@{
        site_type            = $body.site_type
        site_name            = $body.site_name
        desired_state        = $body.desired_state
        site_connection_info = $redactedConnInfo
    }
    $redactedJson = $redactedBody | ConvertTo-Json -Depth 6

    $path = '/sites'
    if ($Force) { $path += '?force=true' }

    $result = Invoke-SspInstanceApi -Connection $Connection -Method POST -Path $path `
        -BodyJson $json -RedactedBodyJson $redactedJson -Troubleshoot:$Troubleshoot

    if ($PollStatus -and $result.id) {
        do {
            Start-Sleep -Seconds 5
            $site = Invoke-SspInstanceApi -Connection $Connection -Method GET -Path "/sites/$($result.id)" -Troubleshoot:$Troubleshoot
            $status = $site.status.configuration_status.current_status
            Write-Host ("Status: {0}  {1}" -f $status, $site.status.configuration_status.configuration_message)
        } while ($status -eq 'ONBOARD_IN_PROGRESS')
        return $site
    }
    return $result
}

Function Remove-SspInstanceNsx {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Offboards and removes an NSX Manager from a deployed SSP Instance
        .DESCRIPTION
            This cmdlet DELETEs an NSX_MANAGER site from the SSP Instance
            (DELETE /ssp/sites/{site-id}). This is a destructive operation and
            executes immediately (offboarding itself runs asynchronously on
            the platform side — poll Get-SspInstanceNsx -NsxManagerId until
            it 404s to confirm completion). Unless -Force is passed, NSX
            Manager admin credentials are required so SSP can clean up
            platform-specific artifacts on the manager itself.
        .PARAMETER Connection
            The SSP instance connection object returned by Connect-SspInstance.
            Defaults to the session's connection, so you don't need to pass this.
        .PARAMETER NsxManagerId
            The site ID of the NSX Manager to remove (see Get-SspInstanceNsx)
        .PARAMETER NsxCredential
            NSX Manager admin credential, used once to clean up
            platform-specific artifacts on the manager during offboarding.
            Required unless -Force is passed. Prompted for if omitted and
            required.
        .PARAMETER Force
            Offboard on a best-effort basis, ignoring errors communicating
            with the NSX Manager (e.g. if it's unreachable). The site is still
            removed from SSP, but references to SSP may remain on the manager
            — re-onboarding it elsewhere may then require -Force there too.
        .PARAMETER Troubleshoot
            Print the HTTP method, URI, and request body (with secrets
            redacted) sent to the API, without affecting the actual request.

        .EXAMPLE
            Remove-SspInstanceNsx -NsxManagerId 2dc09816-34c0-43fb-99a6-b19b249a43da

        .EXAMPLE
            Remove-SspInstanceNsx -NsxManagerId 2dc09816-34c0-43fb-99a6-b19b249a43da -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$Connection = $script:SspInstanceConnection,
        [Parameter(Mandatory)][string]$NsxManagerId,
        [PSCredential]$NsxCredential,
        [switch]$Force,
        [switch]$Troubleshoot
    )
    Assert-SspInstanceConnection $Connection
    if (-not $Force -and -not $NsxCredential) {
        $NsxCredential = Get-Credential -Message "NSX Manager admin credentials to offboard NSX Manager '$NsxManagerId' (required unless -Force)"
    }

    $json = $null
    $redactedJson = $null
    if ($NsxCredential) {
        $credBody = [ordered]@{ username = $NsxCredential.UserName; password = $NsxCredential.GetNetworkCredential().Password }
        $json = $credBody | ConvertTo-Json
        $redactedJson = (Copy-RedactedHashtable -Source $credBody -RedactKeys 'password') | ConvertTo-Json
    }

    $path = "/sites/$NsxManagerId"
    if ($Force) { $path += '?force=true' }

    Invoke-SspInstanceApi -Connection $Connection -Method DELETE -Path $path `
        -BodyJson $json -RedactedBodyJson $redactedJson -Troubleshoot:$Troubleshoot
    Write-Host "NSX Manager site '$NsxManagerId' offboard request accepted."
}
