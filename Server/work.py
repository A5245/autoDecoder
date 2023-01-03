from typing import Dict, Any

from framework import BaseModel, Packet, Framework


class Decrypt(BaseModel):
    def on_request(self, data: Packet) -> Dict[str, Any]:
        """处理请求数据

        :param data: Burp中请求数据
        :return: 修改后的数据
        """
        data.add_header("Test", "Request")
        print(f"requestUrl:\t{data.url}\nbody:\t{data.body}")
        return data.to_data()

    def on_response(self, data: Packet) -> Dict[str, Any]:
        """处理响应数据

        :param data: Burp中响应数据
        :return: 修改后的数据
        """
        data.add_header("Test", "Response")
        print(f"response:\t{data.body}")
        return data.to_data()


def main():
    Framework("server", Decrypt()).start()


if __name__ == '__main__':
    main()
