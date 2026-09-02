# Windows telemetry collection

CyberBug reads only authorized Windows security-event metadata. It does not capture passwords, keystrokes, screen content, personal files, audio, or video.

## Local Security-log collector

Run this component on the Windows endpoint or on the same Windows host where the Security log is available. It requires Python 3.12+ and `pywin32`:

```powershell
cd C:\CyberBug\backend
py -m pip install -e .
py -m pip install pywin32
$env:CYBERBUG_PSEUDONYMIZATION_SECRET = "replace-with-a-long-random-secret"
$env:CYBERBUG_API_URL = "http://SEC-SRV:8000"
$env:CYBERBUG_COLLECTOR_TOKEN = "optional-token-matching-the-backend"
py -m app.collector.service --source security --interval 30 --max-events 100
```

Use `--interval 0` for a single test pass. The collector stores only a bounded cache of event IDs in `%ProgramData%\CyberBug\collector-state.json`; the backend also deduplicates by event ID. The raw XML and account names are never sent. The SID is HMAC-pseudonymized before the HTTP request.

Enable backend collector-token enforcement by setting the same value on SEC-SRV:

```powershell
$env:CYBERBUG_COLLECTOR_TOKEN = "optional-token-matching-the-backend"
```

For production, terminate TLS at the backend and use an authenticated collector channel. The optional token is an MVP control, not a replacement for mutual TLS or endpoint management.

## WEF/WEC collector

Run this on the Windows Event Collector, not on employee endpoints:

```powershell
py -m app.collector.service --source forwarded --interval 30 --max-events 500
```

The reader consumes the WEC `ForwardedEvents` channel. It uses the original event's `Computer` field as the device context, not the collector hostname.

For a domain source-initiated subscription:

1. On SEC-SRV/WEC, configure WinRM and the Event Collector service with elevated PowerShell or Command Prompt:

   ```powershell
   winrm qc -q
   wecutil qc /q
   ```

2. Create a source-initiated WEC subscription that writes to `ForwardedEvents`, scoped to only the required Security event IDs: 4624, 4625, 4634, 4648, 4672, 4688, 5140, and 5145.
3. On source devices, apply **Computer Configuration → Administrative Templates → Windows Components → Event Forwarding → Configure target Subscription Manager**, then run `gpupdate /force`.
4. To forward Security events, grant `NETWORK SERVICE` membership in **EventLog Readers** as required by Microsoft's WEF guidance.
5. Validate the subscription with `wecutil gr <SubscriptionId>` and verify events appear in the `ForwardedEvents` log before starting the collector.

Use HTTPS and a trusted certificate for non-domain or cross-boundary forwarding. Microsoft's [source-initiated subscription guidance](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) and [wecutil reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil) cover the subscription, transport, and certificate details.

## Telemetry limitations

Security Event Logs are not full endpoint visibility. Without additional endpoint telemetry, this collector may not observe USB copying, memory access, all local file operations, or every process/network action. Sysmon can enrich visibility, but it is an additional endpoint component—not agentless telemetry.
