from colorama import init as colorama_init, Fore, Style
from datetime import datetime
colorama_init(autoreset=True)


class Log:
    def __init__(self, verbose: int = 1):
        self.verbose = verbose
        self.PAY = Fore.MAGENTA

    def _time(self):
        return datetime.now().strftime("[%H:%M:%S]")

    def _fmt(self, level: str, color: str):
        return f"{self._time()} {color}[{level}]{Style.RESET_ALL}"

    def info(self, msg: str):
        if self.verbose >= 1:
            print(f"{self._fmt('INFO', Fore.CYAN)} {msg}")

    def warn(self, msg: str):
        if self.verbose >= 0:
            print(f"{self._fmt('WARNING', Fore.YELLOW)} {msg}")

    def ok(self, msg: str):
        print(f"{self._fmt('SUCCESS', Fore.GREEN)} {msg}")

    def fail(self, msg: str):
        print(f"{self._fmt('FAIL', Fore.RED)} {msg}")

    def debug(self, msg: str):
        if self.verbose >= 2:
            print(f"{self._fmt('DEBUG', Fore.MAGENTA)} {msg}")

    def finding(self, sev: str, vuln: str, loc: str, param: str, payload: str, code: int):
        sev_col = {"high": Fore.RED, "medium": Fore.YELLOW,
                   "low": Fore.GREEN}.get(sev, Fore.WHITE)
        print(f"{self._fmt('CRITICAL', sev_col)} {vuln} "
              f"{loc}.{param} = {Fore.MAGENTA}{payload}{Style.RESET_ALL} "
              f"{Style.DIM}(HTTP {code}){Style.RESET_ALL}")
