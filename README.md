# CVE-2023-21752

PoC for arbitrary file delete vulnerability in Windows Backup service.

https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21752

This repo contains two exploits:

v1 - Just perform file delete of user choice 

v2 - Tries to abuse arb delete to spawn elevated cmd shell (not very stable probably need to run it couple of times, better work on phisycal machine)





https://user-images.githubusercontent.com/44291883/211601142-c04534e5-f718-478d-b91a-65d6a4f06080.mp4


# Timeline

- 07/07/2022 - Vulnerability reported to MSRC
- 08/10/2022 - MSRC confirmed vulnerability 
- 08/12/2022 - Bounty awarded
- 01/10/2023 - Patch released 
