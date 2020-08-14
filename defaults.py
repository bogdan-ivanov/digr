import string

DEFAULT_CONNECTION_COUNT = 100
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 5
DEFAULT_VALID_STATUS_CODES = [200, 204, 301, 302, 307, 401, 403]
ALLOWED_CHARS = string.ascii_letters + string.digits
USER_AGENTS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
)
