# Blind SQLi PCAP Extraction

## Step 1

Extract all POST bodies:

```bash
tshark -r blind_sqli.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data > post_bodies.txt
```

---

## Step 2

Decode them from base64 and remove `username=`:

```bash
while read line; do
  echo "===="
  echo "$line" | xxd -r -p | sed 's/%/\\x/g' | xargs printf '%b' | sed -n 's/.*username=\([^&]*\).*/\1/p' | base64 -d
done < post_bodies.txt > payloads.txt
```

---

## Step 3

Extract characters using Python:

```python
import re

chars = {}

with open("payloads.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = re.search(r"SUBSTR\(password,\s*(\d+)\s*,\s*1\)\s*=\s*'(.{1})'", line)
        if m:
            pos = int(m.group(1))
            ch = m.group(2)
            chars[pos] = ch

for pos in sorted(chars):
    print(chars[pos], end="")

print()
```
