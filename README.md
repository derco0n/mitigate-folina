# mitigate-folina
Mitigates the "Folina"-ZeroDay (CVE-2022-30190) and "Search"-Nightmare (no CVE given at the moment)

This script will backup and then remove the affected registry key (as suggested by Microsoft) to mitigate CVE-2022-30190).
If parameterized with "-revert" the script will reimport the key.
This can be used when Microsoft releases a patch.

Script must be run as administrator or NT-AUTHORITY\SYSTEM (can be deployed via GPP as a startscript or scheduled task)

- https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/
- https://www.heise.de/news/Zero-Day-Luecke-Erste-Cybergangs-greifen-MSDT-Sicherheitsluecke-an-7128265.html
- https://www.heise.de/news/Zero-Day-Luecke-in-MS-Office-Microsoft-gibt-Empfehlungen-7126993.html
- https://www.bleepingcomputer.com/news/security/new-windows-search-zero-day-added-to-microsoft-protocol-nightmare/

