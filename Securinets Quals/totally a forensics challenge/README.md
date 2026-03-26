# Securinets Quals: Totally a forensics challenge

---
##  Step 1: Identifying the Handshake Anomaly
When opening the PCAP, your interest should immediately be drawn to the packet containing the **Certificate**. Typically, certificates are standard, but in this specific capture, the server's behavior is the key.
<img width="1125" height="40" alt="{005FE5D9-7FB7-49D2-9263-16F126FFDEB2}" src="https://github.com/user-attachments/assets/7ddd067f-7f5e-473d-a3ef-d1e97ab365a2" /> 
By expanding the **Server Hello** and looking into the **Certificate** section, we can extract the **RSA Public Key** used for this session.
<img width="856" height="198" alt="{64B6E793-4C5B-4267-B74B-2CA58AA05507}" src="https://github.com/user-attachments/assets/e11df7ee-0961-4a3d-86d5-acac8a993ab0" /> 
<img width="956" height="249" alt="{C0DCDD33-64CC-4FB5-A56C-7EEA5582CD83}" src="https://github.com/user-attachments/assets/ccbcdf1b-682e-4d5a-b5f7-0ca78344b545" /> 
---

## Step 2: Exploiting the Weak Key
The extracted RSA key is mathematically weak. This vulnerability allows for a factorization attack (finding $p$ and $q$) to derive the **Private Key** for ourselves. 

Once you have generated the private key (e.g., `private.pem`), you can use it to pull back the curtain on the encrypted data.
<img width="857" height="115" alt="{1C40ADCD-B439-4167-AEF8-F0B0D8361BDC}" src="https://github.com/user-attachments/assets/be095a64-3fce-40f1-824d-653554c2530d" /> 
---

## Step 3: Decrypting the Traffic in Wireshark
To see the plaintext, you must provide Wireshark with the private key. Navigate to:

**Edit** -> **Preferences** -> **Protocols** -> **TLS** -> **RSA Keys List**

1. Click **Edit**.
2. Add a new entry with the Server IP and your generated `.pem` file.
3. Save and refresh the packet list.

---

## Step 4: Finding the Flag
With the private key applied, Wireshark will now successfully decrypt the **HTTP** traffic. By following the SSL/TLS stream or inspecting the response to a **GET request**, the flag will be visible in the decrypted payload.

---
