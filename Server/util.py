def make_response(body_base64: str, order=None, headers=None):
    result = {
        "body": body_base64
    }
    if headers is not None:
        result["headers"] = headers
    if order is not None:
        result["order"] = order
    return result
