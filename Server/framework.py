import base64
import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional

from flask import Flask, request

from util import make_response

app = Flask("server")


class Packet(object):
    """Burp数据包封装"""

    class Type(Enum):
        """数据包类型"""
        REQUEST = 0
        RESPONSE = 1

    class FromInt(Enum):
        """数据包来源"""
        TOOL_PROXY = 0x00000004
        TOOL_INTRUDER = 0x00000020
        TOOL_REPEATER = 0x00000040
        TOOL_EXTENDER = 0x00000400
        EDITOR = 0x00000800

    def __init__(self, _type: Type, from_int: FromInt, url: str, order: List[str], headers: Dict[str, str], body: str):
        """构建数据包

        :param _type: 类型
        :param from_int: 来源
        :param url: 请求URL，type为RESPONSE时为空
        :param order: Header顺序
        :param headers: Header头数据
        :param body: Base64编码的Body数据
        """
        self.__type = _type
        self.__from_int = from_int
        self.__url = url
        self.__order = order
        self.__headers = headers
        self.__body = base64.b64decode(body)
        self.__modified = False

    @property
    def type(self) -> Type:
        return self.__type

    @property
    def from_int(self) -> FromInt:
        return self.__from_int

    @property
    def url(self) -> Optional[str]:
        return self.__url

    @property
    def headers(self) -> Dict[str, str]:
        return self.__headers

    @property
    def body(self) -> bytes:
        return self.__body

    def set_body(self, body: bytes):
        self.__body = body
        self.__modified = True

    def remove_header(self, name: str):
        self.__order.remove(name)
        self.__headers.pop(name)
        self.__modified = True

    def add_header(self, name: str, value: str):
        if name not in self.__order:
            self.__order.append(name)
        self.__headers[name] = value
        self.__modified = True

    @staticmethod
    def create(js: dict):
        """构建数据包

        :param js: 插件发送的json数据
        :return: Packet对象
        """
        from_int = js["from"]
        if from_int == Packet.FromInt.TOOL_PROXY.value:
            from_int = Packet.FromInt.TOOL_PROXY
        elif from_int == Packet.FromInt.TOOL_INTRUDER.value:
            from_int = Packet.FromInt.TOOL_INTRUDER
        elif from_int == Packet.FromInt.TOOL_REPEATER.value:
            from_int = Packet.FromInt.TOOL_REPEATER
        elif from_int == Packet.FromInt.TOOL_EXTENDER.value:
            from_int = Packet.FromInt.TOOL_EXTENDER
        elif from_int == Packet.FromInt.EDITOR.value:
            from_int = Packet.FromInt.EDITOR
        return Packet(Packet.Type.REQUEST if js["type"] == Packet.Type.REQUEST.value else Packet.Type.RESPONSE,
                      from_int, js["url"] if "url" in js else None, js["order"], js["headers"], js["body"])

    def to_data(self) -> Dict[str, Any]:
        """数据返回前解封装

        :return: json数据
        """
        return make_response(base64.b64encode(self.__body).decode(),
                             self.__order if self.__modified else None,
                             self.__headers if self.__modified else None)


class BaseModel(ABC):
    """模型接口"""

    @abstractmethod
    def on_request(self, data: Packet) -> Dict[str, Any]:
        return data.to_data()

    @abstractmethod
    def on_response(self, data: Packet) -> Dict[str, Any]:
        return data.to_data()


def init(impl):
    """初始化模型加载

    :param impl: 继承至BaseModel对象
    """
    app.config["impl"] = impl


@app.route("/do", methods=["POST"])
def do_work():
    if not request.is_json:
        return json.dumps({})
    impl: BaseModel = app.config["impl"]
    packet = Packet.create(request.json)
    result = None
    if packet.type == Packet.Type.REQUEST:
        try:
            result = impl.on_request(packet)
        except:
            result = BaseModel.on_request(impl, packet)
    elif packet.type == Packet.Type.RESPONSE:
        try:
            result = impl.on_response(packet)
        except:
            result = BaseModel.on_response(impl, packet)
    return json.dumps(result)


def start(address: str = "127.0.0.1", port: int = 5000):
    app.run(address, port)
