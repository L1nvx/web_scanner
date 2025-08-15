import random
import string
import re


def _rand(n: int = 8) -> str:
    abc = string.ascii_letters + string.digits
    return "".join(random.choice(abc) for _ in range(n))


class CMDi:
    """
    Command Injection (Unix/Windows) con:
      - Marcador en respuesta: echo/print (si el resultado del comando se refleja).
      - Time-based: sleep/ping/timeout.
    """

    def __init__(self, sleep_s: int = 3, time_threshold: float = 2.2):
        self.name = "Command Injection"
        self.canary = _rand()
        self.sleep_s = sleep_s
        self.time_threshold = time_threshold

        c = self.canary
        s = self.sleep_s

        # Separadores: ; | || && ` $()  $(())
        sep = [";", "|", "||", "&&"]
        unix_echo = [f"echo {c}", f"printf {c}"]
        unix_sleep = [f"sleep {s}", f"ping -c {s} 127.0.0.1"]
        win_echo = [f"echo {c}"]
        win_sleep = [f"timeout /T {s}", f"ping -n {s} 127.0.0.1 >NUL"]

        payloads = set()

        # Unix: salida visible
        for e in unix_echo:
            payloads.update({
                f"{sep_}{e}" for sep_ in sep
            } | {
                f"`{e}`",
                f"$({e})",
            })

        # Unix: solo tiempo
        for t in unix_sleep:
            payloads.update({
                f"{sep_}{t}" for sep_ in sep
            } | {
                f"`{t}`",
                f"$({t})",
            })

        # Windows: salida visible
        for e in win_echo:
            payloads.update({
                f"{sep_}{e}" for sep_ in sep
            })

        # Windows: tiempo
        for t in win_sleep:
            payloads.update({
                f"{sep_}{t}" for sep_ in sep
            })

        # Variantes con cierre de comillas comunes
        quotes = ["", "'", '"', ")"]
        enriched = set()
        for p in payloads:
            for q in quotes:
                enriched.add(q + p)
        self.payloads = list(enriched)

        # regex de detección de canario
        self._canary_rx = re.compile(re.escape(self.canary))

    def get_payloads(self):
        return self.payloads

    def check_response(self, response) -> bool:
        body = response.text or ""

        # 1) contenido reflejado
        if self._canary_rx.search(body):
            return True

        # 2) time-based
        try:
            elapsed = response.elapsed.total_seconds()
            if elapsed >= self.time_threshold:
                return True
        except Exception:
            pass

        return False
