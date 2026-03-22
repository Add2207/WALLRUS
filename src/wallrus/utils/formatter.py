"""
WALLRUS - Terminal Formatter

Rich-based terminal rendering for scan results, dashboards, and logs.
Keeps all display logic out of the CLI and engine modules.
"""

from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.columns import Columns

from wallrus.core.engine import ScanResult, Verdict, MatchDetail
from wallrus.core.signatures import Severity

console = Console()


# ── Colour palette ─────────────────────────────────────────────────────────────
VERDICT_STYLE = {
    Verdict.BLOCKED: "bold red",
    Verdict.FLAGGED: "bold yellow",
    Verdict.CLEAN:   "bold green",
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
}

VERDICT_ICON = {
    Verdict.BLOCKED: "🚫",
    Verdict.FLAGGED: "⚠️ ",
    Verdict.CLEAN:   "✅",
}


# ── Banner ────────────────────────────────────────────────────────────────────
def print_banner() -> None:
    banner = """[bold green]
 ██╗    ██╗ █████╗ ██╗     ██╗     ██████╗ ██╗   ██╗███████╗
 ██║    ██║██╔══██╗██║     ██║     ██╔══██╗██║   ██║██╔════╝
 ██║ █╗ ██║███████║██║     ██║     ██████╔╝██║   ██║███████╗
 ██║███╗██║██╔══██║██║     ██║     ██╔══██╗██║   ██║╚════██║
 ╚███╔███╔╝██║  ██║███████╗███████╗██║  ██║╚██████╔╝███████║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold green]
[dim]  Web Application Firewall · Phase 1 · Signature Engine[/dim]
"""
    console.print(banner)


# ── Scan result card ──────────────────────────────────────────────────────────
def print_result(result: ScanResult) -> None:
    verdict_style = VERDICT_STYLE.get(result.verdict, "white")
    icon          = VERDICT_ICON.get(result.verdict, "?")

    # ── Header panel
    header_text = Text()
    header_text.append(f" {icon}  VERDICT: ", style="bold white")
    header_text.append(result.verdict, style=verdict_style)
    header_text.append(f"   |   Risk Score: ", style="dim white")
    header_text.append(f"{result.risk_score}/100", style=_score_style(result.risk_score))
    header_text.append(f"   |   Scan time: {result.scan_time_ms:.2f}ms", style="dim")
    if result.request_id:
        header_text.append(f"   |   ID: {result.request_id[:8]}…", style="dim")

    console.print(Panel(header_text, border_style=verdict_style.replace("bold ", ""),
                        expand=False))

    if not result.matches:
        console.print("  [dim]No signatures matched — request appears clean.[/dim]\n")
        return

    # ── Match table
    table = Table(
        title=f"[bold]{len(result.matches)} signature(s) matched[/bold]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=True,
        expand=False,
    )
    table.add_column("Rule ID",     style="cyan",   no_wrap=True)
    table.add_column("Name",        style="white",  no_wrap=True)
    table.add_column("Severity",    style="white",  no_wrap=True)
    table.add_column("OWASP",       style="dim",    no_wrap=False, max_width=30)
    table.add_column("Target",      style="blue",   no_wrap=True)
    table.add_column("Matched",     style="yellow", no_wrap=False, max_width=45)

    for m in result.matches:
        sev_style = SEVERITY_STYLE.get(m.severity, "white")
        table.add_row(
            m.rule_id,
            m.rule_name,
            Text(m.severity, style=sev_style),
            m.owasp,
            m.target,
            m.matched_text,
        )

    console.print(table)
    console.print()


# ── Stats dashboard ───────────────────────────────────────────────────────────
def print_stats(stats: dict) -> None:
    console.print(Panel("[bold green]📊  WALLRUS Security Dashboard[/bold green]",
                        border_style="green"))

    # Summary counts
    summary_table = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=False)
    summary_table.add_column("Metric", style="dim")
    summary_table.add_column("Value",  style="bold white")

    summary_table.add_row("Total Scans",    str(stats.get("total_scans", 0)))
    summary_table.add_row("🚫 Blocked",     f"[red]{stats.get('blocked', 0)}[/red]")
    summary_table.add_row("⚠️  Flagged",     f"[yellow]{stats.get('flagged', 0)}[/yellow]")
    summary_table.add_row("✅ Clean",        f"[green]{stats.get('clean', 0)}[/green]")

    console.print(summary_table)

    # Top triggered rules
    top = stats.get("top_rules", [])
    if top:
        console.print("\n[bold]Top triggered rules:[/bold]")
        rules_table = Table(box=box.MINIMAL, expand=False)
        rules_table.add_column("Rule",  style="cyan")
        rules_table.add_column("Hits",  style="bold white", justify="right")
        for entry in top:
            rules_table.add_row(entry["rule"], str(entry["count"]))
        console.print(rules_table)

    console.print()


# ── Recent logs table ─────────────────────────────────────────────────────────
def print_recent_logs(rows: list) -> None:
    if not rows:
        console.print("[dim]No scan records found.[/dim]")
        return

    table = Table(
        title="[bold]Recent Scans[/bold]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=False,
    )
    table.add_column("Timestamp",   style="dim",   no_wrap=True)
    table.add_column("Method",      style="cyan",  no_wrap=True)
    table.add_column("Host",        style="white", no_wrap=True)
    table.add_column("Path",        style="white", no_wrap=False, max_width=30)
    table.add_column("Verdict",     style="white", no_wrap=True)
    table.add_column("Score",       style="white", no_wrap=True, justify="right")

    for row in rows:
        verdict   = row.get("verdict", "?")
        v_style   = VERDICT_STYLE.get(verdict, "white")
        score     = row.get("risk_score", 0)
        table.add_row(
            row.get("timestamp", "")[:19],
            row.get("method", "?"),
            row.get("host") or "—",
            row.get("path", ""),
            Text(verdict, style=v_style),
            Text(str(score), style=_score_style(score)),
        )

    console.print(table)
    console.print()


# ── Signature ruleset table ───────────────────────────────────────────────────
def print_signatures(signatures: list) -> None:
    table = Table(
        title="[bold]Loaded Signature Rules[/bold]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=True,
    )
    table.add_column("ID",       style="cyan",  no_wrap=True)
    table.add_column("Name",     style="white", no_wrap=False, max_width=28)
    table.add_column("Severity", style="white", no_wrap=True)
    table.add_column("OWASP",    style="dim",   no_wrap=False, max_width=32)
    table.add_column("Targets",  style="blue",  no_wrap=True)

    for sig in signatures:
        sev_style = SEVERITY_STYLE.get(sig.severity, "white")
        table.add_row(
            sig.id,
            sig.name,
            Text(sig.severity, style=sev_style),
            sig.owasp,
            ", ".join(sig.targets),
        )

    console.print(table)


# ── Error / info helpers ──────────────────────────────────────────────────────
def print_error(msg: str) -> None:
    console.print(f"[bold red]✗ Error:[/bold red] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[dim]ℹ  {msg}[/dim]")


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}")


# ── Utility ───────────────────────────────────────────────────────────────────
def _score_style(score: int) -> str:
    if score >= 60:
        return "bold red"
    if score >= 30:
        return "yellow"
    return "green"
