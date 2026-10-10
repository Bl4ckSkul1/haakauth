"""
colors.py — Terminal colors and output formatting for HaakAuth.
Same visual style as HaakWAF; professional pentesting tool output.
"""
import sys
import os

# ── Códigos ANSI ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
NEGRITA = "\033[1m"
VERDE   = "\033[92m"
ROJO    = "\033[91m"
AMARILLO= "\033[93m"
CIAN    = "\033[96m"
BLANCO  = "\033[97m"
GRIS    = "\033[90m"
NARANJA = "\033[38;5;208m"
AZUL    = "\033[94m"
MAGENTA = "\033[95m"

# Windows: forzar modo ANSI si es posible
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32          # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _no_color() -> bool:
    """Devuelve True si el entorno no soporta color o el usuario lo deshabilita."""
    return os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Aplica color solo si el terminal lo soporta."""
    if _no_color():
        return text
    return f"{code}{text}{RESET}"


# ── Banner ────────────────────────────────────────────────────────────────────

def banner() -> None:
    """ASCII art banner — HaakAuth."""
    art = rf"""
{NEGRITA}{CIAN}
  ██╗  ██╗ █████╗  █████╗ ██╗  ██╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
  ██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
  ███████║███████║███████║█████╔╝ ███████║██║   ██║   ██║   ███████║
  ██╔══██║██╔══██║██╔══██║██╔═██╗ ██╔══██║██║   ██║   ██║   ██╔══██║
  ██║  ██║██║  ██║██║  ██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{RESET}
{NEGRITA}{BLANCO}        Authentication & Authorization Security Tester{RESET}
{GRIS}        By Adrian Martinez | HAAK Cybersecurity Consulting{RESET}
{GRIS}        ─────────────────────────────────────────────────{RESET}
"""
    print(art)


# ── Section headers ───────────────────────────────────────────────────────────

def section(title: str) -> None:
    """Encabezado de sección con bordes ══════ en cian."""
    width = 60
    border = "═" * width
    pad = max(0, width - len(title) - 4)
    left = pad // 2
    right = pad - left
    line = f"  ══{'═' * left}[ {title} ]{'═' * right}══"
    print(f"\n{_c(CIAN + NEGRITA, line)}")


# ── Mensajes de estado ────────────────────────────────────────────────────────

def msg_ok(text: str) -> None:
    """[+] verde — éxito / encontrado."""
    print(f"  {_c(VERDE + NEGRITA, '[+]')} {text}")


def msg_fail(text: str) -> None:
    """[-] rojo — fallo / no vulnerable."""
    print(f"  {_c(ROJO + NEGRITA, '[-]')} {text}")


def msg_info(text: str) -> None:
    """[*] cian — información neutral."""
    print(f"  {_c(CIAN, '[*]')} {text}")


def msg_warn(text: str) -> None:
    """[!] amarillo — advertencia."""
    print(f"  {_c(AMARILLO + NEGRITA, '[!]')} {text}")


# ── Vulnerabilidades ──────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "critical": ROJO + NEGRITA,
    "high":     NARANJA + NEGRITA,
    "medium":   AMARILLO + NEGRITA,
    "low":      VERDE,
    "info":     AZUL,
}

_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high":     "HIGH    ",
    "medium":   "MEDIUM  ",
    "low":      "LOW     ",
    "info":     "INFO    ",
}


def msg_vuln(severity: str, text: str) -> None:
    """Hallazgo de vulnerabilidad con color por severidad."""
    sev = severity.lower()
    color = _SEVERITY_COLORS.get(sev, BLANCO)
    label = _SEVERITY_LABELS.get(sev, sev.upper().ljust(8))
    print(f"  {_c(color, f'[{label}]')} {text}")


# ── Progress bar ──────────────────────────────────────────────────────────────

def progress_bar(current: int, total: int, label: str = "") -> None:
    """Barra de progreso inline con porcentaje."""
    if total == 0:
        return
    pct = current / total
    filled = int(40 * pct)
    bar = f"[{'█' * filled}{'░' * (40 - filled)}]"
    pct_str = f"{pct * 100:5.1f}%"
    suffix = f"  {current}/{total}"
    if label:
        suffix += f"  {label}"
    # \r para sobreescribir la línea; flush inmediato
    sys.stdout.write(f"\r  {_c(CIAN, bar)} {pct_str}{GRIS}{suffix}{RESET}")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ── Tablas ────────────────────────────────────────────────────────────────────

def table_header(columns: list[str]) -> None:
    """Imprime encabezado de tabla con separador."""
    widths = [max(len(c), 12) for c in columns]
    header = "  " + "  ".join(c.ljust(w) for c, w in zip(columns, widths))
    sep    = "  " + "  ".join("─" * w for w in widths)
    print(_c(NEGRITA + BLANCO, header))
    print(_c(GRIS, sep))


def table_row(values: list[str], colors: list[str] | None = None) -> None:
    """Imprime fila de tabla.  colors es lista de códigos ANSI opcionales."""
    if colors is None:
        colors = [""] * len(values)
    # Rellenar colores faltantes
    while len(colors) < len(values):
        colors.append("")

    widths = [max(len(str(v)), 12) for v in values]
    parts = []
    for val, color, width in zip(values, colors, widths):
        cell = str(val).ljust(width)
        parts.append(_c(color, cell) if color else cell)
    print("  " + "  ".join(parts))


# ── Status codes ──────────────────────────────────────────────────────────────

def status_code_color(code: int) -> str:
    """Devuelve el código HTTP coloreado según su clase."""
    s = str(code)
    if code < 300:
        return _c(VERDE + NEGRITA, s)
    if code < 400:
        return _c(AZUL, s)
    if code < 500:
        return _c(AMARILLO + NEGRITA, s)
    return _c(ROJO + NEGRITA, s)
