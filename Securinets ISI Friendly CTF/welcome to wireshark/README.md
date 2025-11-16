# Challenge: Dns Tunneling

**Category:** Forensics | Network Analysis  
**Points:** 100  
**Difficulty:** Easy  

---

## Description

Wireshark is the most popular tool for packet analysis it lets you inspect packets to see what they carry, you're gonna need that for this challenge.

The flag format is: `Securinets{...}`

---
## Solution
```bash
wireshark tcp_flag.pcap
```

you can immediatly note that the pcap is full of TCP and SSH  only packets you can manually inspect them or just follow the tcp conversations to find that the flag was just pinged over TCP
and it shows stuff in plaintext due to no secure protocol hiding its output so you can just find the flag in the first TCP conversation




