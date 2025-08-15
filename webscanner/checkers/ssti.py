import random
import string
import re


def generate_random_string(length: int) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


class SSTI:
    def __init__(self):
        self.name = "Server-Side Template Injection (SSTI)"
        self.canary = generate_random_string(8)
        self.payloads = [
            self.canary + "{{7*7}}",
            self.canary + "${7*7}",
            self.canary + "#{7*7}",
            self.canary + "<%= 7*7 %>",
            self.canary + "${{7*7}}",
            self.canary + "{{= 7*7}}",
            self.canary + "{% 7*7 %}",
            self.canary + "<#= 7*7 #>",
            self.canary + "[7*7]",
            self.canary + "[[7*7]]",
            self.canary + "*(7*7)",
            self.canary + "@(7*7)"
        ]

    def get_payloads(self): return self.payloads

    def check_response(self, response) -> bool:
        return bool(re.search(re.escape(self.canary) + r".*49", response.text, re.S))
