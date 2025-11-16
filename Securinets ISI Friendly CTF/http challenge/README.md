# Challenge: http exfiltration

**Category:** Forensics | Network Analysis  
**Points:** 400  
**Difficulty:** Easy  

---

## Description
Our friend downloaded something over an insecure protocol once again, it was a web app and he said something about an audio file with beeps can you recover the file and tell me what it says?


The flag format is: `Securinets{...}`

---
## Solution
```bash
wireshark capture.pcap
```

If we analyze the file with wireshark we can find that the user sent a GET request for a file called flag_audio.wav, wireshark lets you reassemble files from its user interface
we use that and get the file flag_audio.wav which is a morse code looking for a morse code decoder online we can retrieve the flag!




