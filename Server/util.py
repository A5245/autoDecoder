def make_response(body_base64: str, order=None, headers=None):
    if headers is None:
        headers = []
    if order is None:
        order = []
    return {
        "headers": headers,
        "order": order,
        "body": body_base64
    }
