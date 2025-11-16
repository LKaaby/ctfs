# Challenge: Dns Tunneling

**Category:** Forensics | Network Analysis  
**Points:** 350  
**Difficulty:** Medium  

---

## Description

our friend Firas Souid clicked on a suspicious link which then led to very suspicious behavior on his network, can you uncover what happened then get the flag?  

The flag format is: `Securinets{...}`

---
## Solution
```bash
wireshark full_challenge_b64.pcap
```

Observing the packets along with the description we can see the user clicked a link which we could think 2 things either http or any link related Protocols, if we look we can observe
DNS packets that have this format **base64.evil-website.com** and we can find that this appears multiple times if we assemble the base 64 chunks and decode them
we get the flag!



