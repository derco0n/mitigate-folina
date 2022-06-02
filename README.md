# mitigate-folina
Mitigates the "Folina"-ZeroDay (CVE-2022-30190)

This script will backup and then remove the affected registry key (as suggested by Microsoft) to mitigate CVE-2022-30190).
If parameterized with "-revert" the script will reimport the key. This cam be used wehn Microsoft releases a patch
