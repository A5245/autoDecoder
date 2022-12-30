def make_response(body_base64: str, headers=None):
    if headers is None:
        headers = []
    return {
        "headers": headers,
        "body": body_base64
    }
