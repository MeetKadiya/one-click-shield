#!/usr/bin/env python3
"""
"One-Click Shield" Unified Scanner & Auto-Remediator CLI
Command-line security assessment and automated configuration generator.
"""

import os
import sys
import asyncio
import argparse
import json
from pathlib import Path

if sys.platform == "win32":
    import io
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add backend directory to sys.path so it works standalone
backend_dir = Path(__file__).resolve().parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from core.engine import UnifiedScannerEngine
from core.remediator import AutoRemediator

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    Console = None



def print_banner(console):
    banner = """
  ██████╗ ███╗   ██╗███████╗      ██████╗██╗     ██╗ ██████╗██╗  ██╗
 ██╔═══██╗████╗  ██║██╔════╝     ██╔════╝██║     ██║██╔════╝██║ ██╔╝
 ██║   ██║██╔██╗ ██║█████╗       ██║     ██║     ██║██║     █████═╝ 
 ██║   ██║██║╚██╗██║██╔══╝       ██║     ██║     ██║██║     ██╔═██╗ 
 ╚██████╔╝██║ ╚████║███████╗     ╚██████╗███████╗██║╚██████╗██║  ██╗
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝      ╚═════╝╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝
     🛡️  ONE-CLICK SHIELD: Unified Scanner & Auto-Remediator 🛡️
    [Kalpvruksh 2.0 Hackathon • Web Security Configuration Defense]
"""
    if console:
        console.print(Panel(banner, style="bold cyan"))
    else:
        print(banner)


def render_terminal_report(console, result, selected_browser: str = "all"):
    score_data = result.get("score", {})
    target = result.get("target", "unknown")
    score = score_data.get("overall_score", 0)
    grade = score_data.get("grade", "F")
    status = score_data.get("posture_status", "Audited")

    # Color grading
    grade_style = "bold green" if score >= 85 else ("bold yellow" if score >= 70 else "bold red")

    # Score Panel
    summary_panel = Panel(
        f"[bold]Target Host:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Security Grade:[/bold] [{grade_style}]{grade}[/{grade_style}]  |  "
        f"[bold]Score:[/bold] [{grade_style}]{score}/100[/{grade_style}]\n"
        f"[bold]Status:[/bold] {status}\n\n"
        f"[italic]{score_data.get('executive_summary', '')}[/italic]",
        title="[bold green]🛡️ Scan Executive Summary[/bold green]",
        border_style="cyan"
    )
    console.print(summary_panel)

    # Category Breakdown Table
    cat_table = Table(title="📊 Security Posture Breakdown", border_style="blue")
    cat_table.add_column("Category", style="cyan", justify="left")
    cat_table.add_column("Score", justify="center")
    cat_table.add_column("Issues Found", justify="center")

    for cat_key, cat in score_data.get("category_breakdown", {}).items():
        c_score = cat.get("score", 0)
        c_style = "green" if c_score >= 85 else ("yellow" if c_score >= 70 else "red")
        cat_table.add_row(
            cat.get("label", cat_key),
            f"[{c_style}]{c_score}/100[/{c_style}]",
            str(cat.get("issues_count", 0))
        )
    console.print(cat_table)

    # Multi-Browser Compatibility & Security Matrix Table
    browser_data = result.get("browser_matrix", {})
    browser_matrix = browser_data.get("browsers", {})
    avg_browser_score = browser_data.get("overall_browser_score", 0)

    if browser_matrix:
        b_table = Table(
            title=f"🌐 Multi-Browser Compatibility & Threat Matrix (Avg Rating: {avg_browser_score}/100)",
            border_style="magenta"
        )
        b_table.add_column("Browser & Engine", style="bold", justify="left")
        b_table.add_column("Score", justify="center")
        b_table.add_column("Status", justify="center")
        b_table.add_column("Engine Threat Model Focus", style="cyan")
        b_table.add_column("Security Engine Verdict", style="dim")

        status_styles = {
            "SHIELDED": "bold green",
            "WARNINGS_PRESENT": "bold yellow",
            "BLOCKED_RISK": "bold red"
        }

        display_keys = ["brave", "tor", "yandex", "chrome", "firefox", "safari"]
        if selected_browser and selected_browser.lower() != "all" and selected_browser.lower() in browser_matrix:
            display_keys = [selected_browser.lower()]

        for b_key in display_keys:
            b_info = browser_matrix.get(b_key)
            if not b_info:
                continue
            b_score = b_info.get("score", 0)
            b_status = b_info.get("status", "WARNINGS_PRESENT")
            b_style = status_styles.get(b_status, "white")
            b_table.add_row(
                f"{b_info.get('icon', '🌐')} {b_info.get('name', b_key.title())}\n[dim]({b_info.get('engine', '')})[/dim]",
                f"{b_score}/100",
                f"[{b_style}]{b_status.replace('_', ' ')}[/{b_style}]",
                b_info.get("threat_model", ""),
                b_info.get("verdict", "")
            )
        console.print(b_table)

        # Detailed Browser Findings Panel
        findings_sections = []
        for b_key in display_keys:
            b_info = browser_matrix.get(b_key)
            if not b_info:
                continue
            findings = b_info.get("findings", [])
            f_lines = []
            for f in findings:
                f_type = f.get("type", "INFO")
                f_title = f.get("title", "")
                f_desc = f.get("desc", "")
                if f_type == "CRITICAL":
                    f_lines.append(f"  [bold red]❌ {f_title}[/bold red]: {f_desc}")
                elif f_type == "WARNING":
                    f_lines.append(f"  [bold yellow]⚠️  {f_title}[/bold yellow]: {f_desc}")
                elif f_type in ["PASS", "EXCELLENT"]:
                    f_lines.append(f"  [green]✓ {f_title}[/green]: {f_desc}")
                else:
                    f_lines.append(f"  [dim]ℹ️  {f_title}: {f_desc}[/dim]")
            
            findings_block = "\n".join(f_lines) if f_lines else "  [dim]No engine alerts triggered.[/dim]"
            b_status = b_info.get("status", "WARNINGS_PRESENT")
            b_style = status_styles.get(b_status, "white")
            findings_sections.append(
                f"{b_info.get('icon', '🌐')} [bold]{b_info.get('name')}[/bold] [{b_style}][{b_info.get('score')}/100 - {b_status.replace('_', ' ')}][/{b_style}]\n"
                f"   [dim]Verdict:[/dim] {b_info.get('verdict')}\n"
                f"{findings_block}"
            )

        detail_panel = Panel(
            "\n\n".join(findings_sections),
            title="[bold magenta]🔍 Browser Engine Defense Analysis (Brave, Tor, Yandex, Chrome, Firefox, Safari)[/bold magenta]",
            border_style="magenta"
        )
        console.print(detail_panel)

    issues = score_data.get("all_issues", [])
    if issues:
        issue_table = Table(title=f"⚠️  Detected Vulnerabilities & Weaknesses ({len(issues)})", border_style="red")
        issue_table.add_column("Severity", justify="center", style="bold")
        issue_table.add_column("Category", style="cyan")
        issue_table.add_column("Vulnerability Title", style="white")
        issue_table.add_column("Impact Summary", style="dim")

        sev_colors = {
            "CRITICAL": "bold red on black",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "dim"
        }

        for issue in issues[:15]:  # show top 15 in console
            sev = issue.get("severity", "INFO").upper()
            color = sev_colors.get(sev, "white")
            issue_table.add_row(
                f"[{color}]{sev}[/{color}]",
                issue.get("category", "General"),
                issue.get("title", "Untitled"),
                issue.get("impact", "")[:60] + "..." if len(issue.get("impact", "")) > 60 else issue.get("impact", "")
            )
        console.print(issue_table)
        if len(issues) > 15:
            console.print(f"[dim]... and {len(issues) - 15} more issues. View full report in Web UI or JSON output.[/dim]")
    else:
        console.print("[bold green]✨ No security configuration weaknesses detected! Outstanding posture.[/bold green]")


async def main_async():
    parser = argparse.ArgumentParser(
        description="One-Click Shield: Unified Web Security Scanner & Auto-Remediator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick Usage Examples:
  python shield.py google.com                   # Direct scan of google.com
  python shield.py https://github.com           # Direct scan with full URL
  python shield.py scan badssl.com              # Explicit scan command
  python shield.py remediate example.com        # Generate auto-remediation configs
  python shield.py --demo                       # Run simulated vulnerable test (vulnerable-demo.site)
  python shield.py --browser tor google.com     # Deep-dive Tor Browser analysis
  python shield.py --format json google.com     # Output complete machine-readable JSON
"""
    )
    parser.add_argument("arg1", nargs="?", default=None, help="Target domain (e.g. google.com) or action (scan, remediate, demo)")
    parser.add_argument("arg2", nargs="?", default=None, help="Target domain if action was specified (e.g. 'scan google.com')")
    parser.add_argument("-t", "--target", dest="target", help="Explicit target domain or URL to scan")
    parser.add_argument("-c", "--command", choices=["scan", "remediate", "interactive"], help="Action to perform")
    parser.add_argument("--demo", action="store_true", help="Run simulated vulnerable scenario (vulnerable-demo.site)")
    parser.add_argument("--browser", choices=["tor", "brave", "yandex", "chrome", "firefox", "safari", "all"], default="all", help="Filter browser matrix output to specific browser")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--output", help="Save scan output to JSON file")
    parser.add_argument("--out-dir", default="./shield-fixes", help="Output directory for generated remediation configs")

    args = parser.parse_args()
    console = Console(legacy_windows=False) if Console else None

    print_banner(console)

    command = args.command or "scan"
    target = args.target

    # Determine command and target flexibly from positional arguments
    if args.arg1:
        if args.arg1.lower() in ["scan", "remediate", "interactive"]:
            command = args.arg1.lower()
            if args.arg2:
                target = args.arg2
        elif args.arg1.lower() in ["demo", "--demo"]:
            command = "scan"
            args.demo = True
        else:
            # First argument is directly the target domain! e.g. "python shield.py google.com"
            target = args.arg1
            if args.arg2 and args.arg2.lower() in ["scan", "remediate"]:
                command = args.arg2.lower()

    scenario = None
    if args.demo:
        scenario = "demo-vulnerable"
        target = "vulnerable-demo.site"
    elif not target or command == "interactive":
        if console:
            console.print("\n[bold yellow]Enter target domain to scan (e.g. google.com, badssl.com, or 'demo'):[/bold yellow]")
            user_input = input("Target: ").strip()
        else:
            user_input = input("Target domain (or 'demo'): ").strip()

        if not user_input or user_input.lower() == "demo":
            if console:
                console.print("[bold yellow]No domain entered. Running demonstration against simulated vulnerable site (vulnerable-demo.site)...[/bold yellow]\n")
            scenario = "demo-vulnerable"
            target = "vulnerable-demo.site"
        elif "vulnerable" in user_input.lower():
            scenario = "demo-vulnerable"
            target = "vulnerable-demo.site"
        elif "secure" in user_input.lower():
            scenario = "demo-secure"
            target = "hardened-example.org"
        else:
            scenario = None
            target = user_input
    else:
        # Check if target is a known mock scenario
        if target.lower() in ["vulnerable-demo.site", "demo-vulnerable.local"]:
            scenario = "demo-vulnerable"
            target = "vulnerable-demo.site"
        elif target.lower() in ["hardened-example.org", "demo-secure.local"]:
            scenario = "demo-secure"
            target = "hardened-example.org"
        else:
            scenario = None

    engine = UnifiedScannerEngine(timeout=8.0)

    if console:
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}..."),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning target: {target} [SSL/TLS, Headers, Cookies, Redirects]", total=None)
            result = await engine.scan_target(target, is_demo_scenario=scenario)
            progress.update(task, completed=True)
    else:
        print(f"[*] Scanning target: {target} ...")
        result = await engine.scan_target(target, is_demo_scenario=scenario)

    # Persist audit record to SQLite database
    try:
        from core.db import save_scan
        save_scan(result)
    except Exception:
        pass

    # Display or output
    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif console:
        render_terminal_report(console, result, selected_browser=args.browser)

    # Save to output file if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        if console:
            console.print(f"\n[green]💾 Scan report saved to:[/green] {args.output}")

    # Generate Remediations if requested or in interactive mode
    if command in ["remediate", "interactive"]:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        rems = result.get("remediations", {})
        for key in ["nginx", "apache", "caddy", "cloudflare", "nodejs", "docker", "readme"]:
            item = rems.get(key)
            if item:
                file_path = out_dir / item["filename"]
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(item["content"])

        if console:
            console.print(Panel(
                f"[bold green]✨ One-Click Auto-Remediation Pack Generated![/bold green]\n"
                f"Production configuration files successfully written to: [cyan]{out_dir.resolve()}[/cyan]\n"
                f" • [yellow]nginx-hardened.conf[/yellow] (Modern TLS 1.2/1.3, ciphers, HSTS, CSP)\n"
                f" • [yellow].htaccess[/yellow] (Apache mod_headers and mod_rewrite rules)\n"
                f" • [yellow]Caddyfile[/yellow] (Automatic TLS & hardened headers)\n"
                f" • [yellow]cloudflare-rules.json[/yellow] (Edge transformation rules)\n"
                f" • [yellow]security-middleware.js[/yellow] (Node.js Helmet & session flags)\n"
                f" • [yellow]docker-compose.shield.yml[/yellow] (Zero-code reverse proxy drop-in)\n"
                f" • [yellow]README_FIXES.md[/yellow] (Plain-English deployment guide)",
                border_style="green"
            ))


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
