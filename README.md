# Burp转发

当前版本：0.11

Add添加正则匹配URL

![main](https://raw.githubusercontent.com/A5245/autoDecoder/master/pic/main.png)

下方输入框输入Server地址，save保存

Server实现详见work.py，默认绑定127.0.0.1:5000。如需修改，修改start方法传入参数start(address: str, port: int)

# Demo

Server/demo中包含完整的功能演示

demo_server.py为服务端，demo_work.py为插件后端（默认地址为http://127.0.0.1:50000/do）

