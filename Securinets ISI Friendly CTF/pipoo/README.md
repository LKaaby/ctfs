# Challenge: Dns Tunneling

**Category:** Forensics | USBpcap analysis
**Points:** 500  
**Difficulty:** Medium  

---

## Description
My friend seems to be obsessed with some creature he found in instagram but he wouldnt tell me his name, i captured his keyboard clicking sending its name can u uncover it
it will be the flag

The flag format is: `Securinets{}`

---
## Solution
```bash
wireshark usbcap.pcap
```
this isnt your usual network packet there are new types of packets which forces you to google some 

quickly you could learn that you can see the device type from the descriptor which u can find theres a keyboard a chinese one plugged in lol

looking farther in the pcap there is input as HID data googling how to decrypt that either do it by hand or find tools online you can get

"pipotammybeloved"

thats the flag





