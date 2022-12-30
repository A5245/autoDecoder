from typing import Dict, Any

from framework import BaseModel, Packet, init, start


class Decrypt(BaseModel):
    def on_request(self, data: Packet) -> Dict[str, Any]:
        tmp = data.get_all()
        tmp["headers"].append("Test: Request")
        return tmp

    def on_response(self, data: Packet) -> Dict[str, Any]:
        tmp = data.get_all()
        tmp["headers"].append("Test: Response")
        return tmp


def main():
    init(Decrypt())
    start()


if __name__ == '__main__':
    main()
