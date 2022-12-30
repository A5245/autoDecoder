import base64
import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any

from flask import Flask, request

from util import make_response

app = Flask("server")


class Packet(object):
    class Type(Enum):
        REQUEST = 0
        RESPONSE = 1

    def __init__(self, _type: Type, from_int: int, url: str, headers: Dict[str, str], body: str):
        self.__type = _type
        self.__from_int = from_int
        self.__url = url
        self.__headers = headers
        self.__body = base64.b64decode(body)

    @property
    def type(self) -> Type:
        return self.__type

    @property
    def from_int(self) -> int:
        return self.__from_int

    @property
    def url(self) -> str:
        return self.__url

    @property
    def headers(self) -> Dict[str, str]:
        return self.__headers

    @property
    def body(self) -> bytes:
        return self.__body

    @staticmethod
    def create(js: dict):
        return Packet(Packet.Type.REQUEST if js["type"] == Packet.Type.REQUEST.value else Packet.Type.RESPONSE,
                      js["from"], js["url"] if "url" in js else None, js["headers"], js["body"])

    def get_all(self) -> Dict[str, Any]:
        return make_response(base64.b64encode(self.body).decode(), self.headers)


class BaseModel(ABC):
    @abstractmethod
    def on_request(self, data: Packet) -> Dict[str, Any]:
        return data.get_all()

    @abstractmethod
    def on_response(self, data: Packet) -> Dict[str, Any]:
        return data.get_all()


def init(impl):
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
