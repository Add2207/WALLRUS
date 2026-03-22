"""
WALLRUS CLI
===========
Entry point for the WALLRUS Web Application Firewall tool.

Commands
--------
  scan       Analyse a raw HTTP request (from stdin, file, or interactive prompt)
  analyze    Alias for scan with verbose output
  logs       View recent scan history from SQLite
  stats      Display security dashboard & aggregate statistics
  rules      List all loaded signature rules
  interactive  Drop into an interactive REPL loop

Run `wallrus --help` or `wallrus <command> --help` for usage.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm

# ── Lazy imports (keep startup fast) ──────────────────────────────────────────
# Proper imports are inside functions to avoid circular-import issues during
# initial development; they can be hoisted once the project stabilises.

console = Console()
app     = typer.Typer(
    name="wallrus",
    help="🦦  WALLRUS — CLI Web Application Firewall",
    add_completion=False,
    rich_markup_mode="rich",
)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_pipeline():
    from wallrus.core.engine import DetectionPipeline
    return DetectionPipeline()


def _get_logger(log_dir: Optional[Path] = None):
    from wallrus.utils.logger import WAFLogger
    return WAFLogger(log_dir=log_dir)


def _parse(raw: str):
    from wallrus.core.parser import parse_http_request, ParseError
    try:
        return parse_http_request(raw), None
    except ParseError as e:
        return None, str(e)


def _run_scan(raw: str, verbose: bool, log_dir: Optional[Path], no_log: bool):
    """Core scan logic shared by `scan` and `interactive` commands."""
    from wallrus.utils.formatter import (
        print_result, print_error, print_info, console as fmt_console
    )

    request, err = _parse(raw)
    if err:
        print_error(f"Could not parse request: {err}")
        return

    pipeline = _get_pipeline()
    result   = pipeline.analyze(request)

    if not no_log:
        logger = _get_logger(log_dir)
        req_id = logger.log(request, result)
        print_info(f"Logged as request_id: {req_id[:8]}…")

    print_result(result)

    if verbose and result.matches:
        fmt_console.print("[bold]Full matched payloads:[/bold]")
        for m in result.matches:
            fmt_console.print(
                f"  [cyan]{m.rule_id}[/cyan] ({m.target}): "
                f"[yellow]{m.matched_text!r}[/yellow]"
            )
        fmt_console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """WALLRUS — Web Application Firewall CLI"""
    if ctx.invoked_subcommand is None:
        from wallrus.utils.formatter import print_banner
        print_banner()
        console.print("  Run [bold cyan]wallrus --help[/bold cyan] to see available commands.\n")


# ── scan ──────────────────────────────────────────────────────────────────────
@app.command()
def scan(
    file: Optional[Path] = typer.Option(
        None, "--file", "-f",
        help="Path to a file containing a raw HTTP request.",
        exists=True, readable=True,
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show full matched payloads.",
    ),
    no_log: bool = typer.Option(
        False, "--no-log",
        help="Skip writing results to the log database.",
    ),
    log_dir: Optional[Path] = typer.Option(
        None, "--log-dir",
        help="Custom directory for log files (default: ./logs).",
    ),
):
    """
    Scan a raw HTTP request for known attack patterns.

    Examples:

      # From a file
      wallrus scan -f request.txt

      # Pipe from stdin
      cat request.txt | wallrus scan

      # Interactive prompt
      wallrus scan
    """
    from wallrus.utils.formatter import print_banner, print_error
    print_banner()

    # ── Read request text ──────────────────────────────────────────────────
    if file:
        raw = file.read_text(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        # Interactive multi-line entry
        console.print("[dim]Paste your raw HTTP request below.")
        console.print("Enter [bold]END[/bold] on a blank line when done.[/dim]\n")
        lines = []
        try:
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            pass
        raw = "\n".join(lines)

    if not raw.strip():
        print_error("No request data provided.")
        raise typer.Exit(1)

    _run_scan(raw, verbose, log_dir, no_log)


# ── analyze (verbose alias) ───────────────────────────────────────────────────
@app.command()
def analyze(
    file: Optional[Path] = typer.Option(None, "--file", "-f", exists=True, readable=True),
    no_log: bool = typer.Option(False, "--no-log"),
    log_dir: Optional[Path] = typer.Option(None, "--log-dir"),
):
    """
    Verbose scan — equivalent to [cyan]scan --verbose[/cyan].
    Shows full matched payloads and rule descriptions.
    """
    from wallrus.utils.formatter import print_banner, print_error
    print_banner()

    if file:
        raw = file.read_text(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        console.print("[dim]Paste raw HTTP request (END to finish):[/dim]\n")
        lines = []
        try:
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            pass
        raw = "\n".join(lines)

    if not raw.strip():
        print_error("No request data provided.")
        raise typer.Exit(1)

    _run_scan(raw, verbose=True, log_dir=log_dir, no_log=no_log)


# ── logs ──────────────────────────────────────────────────────────────────────
@app.command()
def logs(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of records to show."),
    log_dir: Optional[Path] = typer.Option(None, "--log-dir"),
):
    """View recent scan history."""
    from wallrus.utils.formatter import print_banner, print_recent_logs
    print_banner()
    logger = _get_logger(log_dir)
    rows   = logger.get_recent(limit)
    print_recent_logs(rows)


# ── stats ─────────────────────────────────────────────────────────────────────
@app.command()
def stats(
    log_dir: Optional[Path] = typer.Option(None, "--log-dir"),
):
    """Display aggregate security statistics dashboard."""
    from wallrus.utils.formatter import print_banner, print_stats
    print_banner()
    logger = _get_logger(log_dir)
    data   = logger.get_stats()
    print_stats(data)


# ── rules ─────────────────────────────────────────────────────────────────────
@app.command()
def rules(
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW",
    ),
    owasp: Optional[str] = typer.Option(
        None, "--owasp", "-o",
        help="Filter by OWASP category substring (e.g. 'A03')",
    ),
):
    """List all loaded signature rules."""
    from wallrus.core.signatures import SIGNATURES, get_by_severity, get_by_owasp, summary
    from wallrus.utils.formatter import print_banner, print_signatures, print_info

    print_banner()

    sigs = SIGNATURES
    if severity:
        sigs = get_by_severity(severity)
    if owasp:
        sigs = [s for s in sigs if owasp.lower() in s.owasp.lower()]

    s = summary()
    print_info(
        f"Total rules: {s['total_rules']}  |  "
        f"CRITICAL: {s['by_severity']['CRITICAL']}  "
        f"HIGH: {s['by_severity']['HIGH']}  "
        f"MEDIUM: {s['by_severity']['MEDIUM']}  "
        f"LOW: {s['by_severity']['LOW']}"
    )
    print_signatures(sigs)


# ── interactive ───────────────────────────────────────────────────────────────
@app.command()
def interactive(
    log_dir: Optional[Path] = typer.Option(None, "--log-dir"),
    no_log: bool = typer.Option(False, "--no-log"),
):
    """
    Drop into an interactive REPL loop.

    Available REPL commands:
      scan     — Paste and scan a new HTTP request
      stats    — Show dashboard
      logs     — Show recent scans
      rules    — List loaded rules
      clear    — Clear the screen
      help     — Show this help
      exit     — Quit
    """
    from wallrus.utils.formatter import (
        print_banner, print_stats, print_recent_logs,
        print_signatures, print_info, print_error
    )
    from wallrus.core.signatures import SIGNATURES
    import os

    print_banner()
    console.print("[bold green]Interactive mode[/bold green] — type [bold]help[/bold] for commands.\n")

    while True:
        try:
            cmd = Prompt.ask("[bold cyan]wallrus[/bold cyan]").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if cmd in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/dim]")
            break

        elif cmd in ("scan", "s"):
            console.print("[dim]Paste your HTTP request. Enter END on a blank line to finish.[/dim]\n")
            lines = []
            try:
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    lines.append(line)
            except (EOFError, KeyboardInterrupt):
                pass
            raw = "\n".join(lines)
            if raw.strip():
                _run_scan(raw, verbose=False, log_dir=log_dir, no_log=no_log)
            else:
                print_error("Empty request — nothing to scan.")

        elif cmd in ("stats", "dashboard"):
            logger = _get_logger(log_dir)
            print_stats(logger.get_stats())

        elif cmd in ("logs", "history"):
            logger = _get_logger(log_dir)
            print_recent_logs(logger.get_recent(20))

        elif cmd in ("rules", "signatures"):
            print_signatures(SIGNATURES)

        elif cmd in ("clear", "cls"):
            os.system("clear" if os.name != "nt" else "cls")
            print_banner()

        elif cmd in ("help", "h", "?"):
            console.print("""
[bold]Commands:[/bold]
  [cyan]scan[/cyan]         Paste and scan a new HTTP request
  [cyan]stats[/cyan]        Show security dashboard
  [cyan]logs[/cyan]         Show recent scan history
  [cyan]rules[/cyan]        List loaded signature rules
  [cyan]clear[/cyan]        Clear the terminal
  [cyan]exit[/cyan]         Quit WALLRUS
""")
        else:
            print_info(f"Unknown command: {cmd!r}. Type [bold]help[/bold] for options.")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app()
