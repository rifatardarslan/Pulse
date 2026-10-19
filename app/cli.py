import typer
import time
import os
import httpx
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
from rich.prompt import Prompt

app = typer.Typer()
console = Console()
API_BASE_URL = "http://localhost:8000/api/v1/scans"
SCHEDULES_API_URL = "http://localhost:8000/api/v1/schedules"
VERSION = "2.0.0"
PAGE_SIZE = 20

MAGENTA = "bold magenta"
CYAN = "bold cyan"
NEON_PURPLE = "#bc13fe"
WHITE = "bold white"
GREEN = "bold green"
RED = "bold red"

PULSE_BANNER = r"""
      ___       __
     / _ \__ __/ /__ ___
    / ___/ // / (_-</ -_)
   /_/   \_,_/_/___/\__/

"""


def get_headers() -> dict:
    key = os.getenv("PULSE_API_KEY", "")
    return {"X-API-Key": key} if key else {}


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def render_header():
    banner = Text(PULSE_BANNER, style=MAGENTA)
    console.print(Align.center(banner))
    tagline = Text("Pulse Security Intelligence System ", style=WHITE)
    tagline.append(f"v{VERSION}", style=NEON_PURPLE)
    console.print(Align.center(tagline))
    console.print()


def validate_source(source: str) -> bool:
    github_regex = r"^(https?://)?(www\.)?github\.com/[\w-]+/[\w.-]+/?$"
    if re.match(github_regex, source):
        return True
    return os.path.isdir(source)


# ──────────────────────────────────────────────────────────────
# AI Detay Ekranı + FP Yönetimi
# ──────────────────────────────────────────────────────────────
def show_vuln_ai_detail(vuln: dict, scan_id: str):
    while True:
        clear_screen()
        render_header()

        sev = vuln.get("severity", "INFO")
        sev_style = "bold red" if sev in ["CRITICAL", "HIGH"] else "bold yellow"
        is_fp = vuln.get("is_false_positive", False)
        fp_badge = "  [bold red][FP][/bold red]" if is_fp else ""

        info = (
            f"[bold white]Type:[/bold white]        {vuln.get('vulnerability_type', 'N/A')}{fp_badge}\n"
            f"[bold white]File:[/bold white]        {vuln.get('file_path', 'N/A')}:{vuln.get('line_number', '')}\n"
            f"[bold white]Severity:[/bold white]    [{sev_style}]{sev}[/{sev_style}]\n"
            f"[bold white]Description:[/bold white] {vuln.get('description', 'N/A')}"
        )
        if is_fp:
            reason = vuln.get("false_positive_reason") or "No reason given"
            info += f"\n[bold white]FP Reason:[/bold white]   [dim]{reason}[/dim]"

        console.print(Panel(info, title="[bold cyan]Vulnerability Detail[/bold cyan]", border_style=CYAN, padding=(1, 2)))

        remediations = vuln.get("remediations", [])
        if not remediations:
            rule_id = (vuln.get("raw_evidence") or {}).get("RuleID", "")
            console.print(
                f"\n[bold yellow]⏳ Bu zafiyet icin AI analizi henuz hazir degil.[/bold yellow]\n"
                f"[dim]Not: Ayni kural tipindeki ({rule_id or vuln.get('vulnerability_type', '?')}) "
                f"bir zafiyetin AI analizi tamamlaninca History'den tekrar kontrol edebilirsiniz.[/dim]"
            )
        else:
            for i, rem in enumerate(remediations, 1):
                confidence = rem.get("confidence_score") or 0.0
                model = rem.get("ai_model", "N/A")
                console.print(
                    f"\n[bold cyan]AI Remediation #{i}[/bold cyan]  "
                    f"[dim]model: {model}  |  confidence: {confidence:.0%}[/dim]"
                )
                steps = rem.get("remediation_steps") or ""
                if steps:
                    console.print(Panel(
                        steps,
                        title="[bold white]Remediation Steps[/bold white]",
                        border_style="green",
                        padding=(1, 2),
                    ))
                fix = rem.get("suggested_fix") or ""
                if fix:
                    console.print(Panel(
                        fix,
                        title="[bold white]Suggested Code Fix[/bold white]",
                        border_style=CYAN,
                        padding=(1, 2),
                    ))

        fp_toggle = "[U] Unmark FP" if is_fp else "[F] Mark False Positive"
        console.print(f"\n[dim]{fp_toggle} | Enter to return[/dim]")
        raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()

        if raw == "f" and not is_fp:
            reason = console.input("[dim]Reason (optional, press Enter to skip): [/dim]").strip()
            try:
                r = httpx.patch(
                    f"{API_BASE_URL}/{scan_id}/vulnerabilities/{vuln['id']}/false-positive",
                    json={"reason": reason or None},
                    headers=get_headers(),
                    timeout=10.0,
                )
                if r.status_code == 200:
                    vuln = r.json()
                    console.print("[bold green]✔ Marked as false positive.[/bold green]")
                else:
                    console.print(f"[bold red]Error: {r.text}[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Request failed: {e}[/bold red]")
            time.sleep(1)
        elif raw == "u" and is_fp:
            try:
                r = httpx.patch(
                    f"{API_BASE_URL}/{scan_id}/vulnerabilities/{vuln['id']}/false-positive",
                    json={"reason": None},
                    headers=get_headers(),
                    timeout=10.0,
                )
                if r.status_code == 200:
                    vuln = r.json()
                    console.print("[bold green]✔ False positive removed.[/bold green]")
                else:
                    console.print(f"[bold red]Error: {r.text}[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Request failed: {e}[/bold red]")
            time.sleep(1)
        else:
            break


# ──────────────────────────────────────────────────────────────
# Diff görünümü
# ──────────────────────────────────────────────────────────────
def show_diff_view(scan_id: str):
    clear_screen()
    render_header()
    console.print("[dim]Fetching diff...[/dim]")
    try:
        res = httpx.get(f"{API_BASE_URL}/{scan_id}/diff", headers=get_headers(), timeout=15.0)
        res.raise_for_status()
        diff = res.json()
    except Exception as e:
        console.print(f"[bold red]Diff alınamadı: {e}[/bold red]")
        Prompt.ask("\nPress Enter to return")
        return

    if diff.get("is_first_scan"):
        console.print("\n[bold yellow]ℹ Bu repo için ilk tarama. Karşılaştırılacak önceki tarama yok.[/bold yellow]")
        Prompt.ask("\nPress Enter to return")
        return

    summary = diff.get("summary", {})
    console.print(
        f"\n[bold white]Diff:[/bold white] "
        f"[bold red]{summary.get('new_count', 0)} NEW[/bold red]  "
        f"[bold green]{summary.get('fixed_count', 0)} FIXED[/bold green]  "
        f"[bold yellow]{summary.get('persisting_count', 0)} PERSISTING[/bold yellow]\n"
    )

    def _vuln_table(title: str, vulns: list, border: str):
        if not vulns:
            return
        t = Table(title=title, box=box.ROUNDED, border_style=border, header_style="bold white", expand=True)
        t.add_column("Type", style="white")
        t.add_column("File:Line", style="dim")
        t.add_column("Sev", justify="center", width=10)
        for v in vulns:
            sev = v.get("severity", "")
            sev_fmt = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[red]{sev}[/red]" if sev == "HIGH" else f"[yellow]{sev}[/yellow]"
            t.add_row(
                v.get("vulnerability_type", "N/A"),
                f"{v.get('file_path', '')}:{v.get('line_number', '')}",
                sev_fmt,
            )
        console.print(t)
        console.print()

    _vuln_table(f"[bold red]NEW ({summary.get('new_count', 0)})[/bold red]", diff.get("new", []), "red")
    _vuln_table(f"[bold green]FIXED ({summary.get('fixed_count', 0)})[/bold green]", diff.get("fixed", []), "green")
    _vuln_table(f"[bold yellow]PERSISTING ({summary.get('persisting_count', 0)})[/bold yellow]", diff.get("persisting", []), "yellow")

    Prompt.ask("[dim]Press Enter to return[/dim]")


# ──────────────────────────────────────────────────────────────
# HTML Rapor dışa aktarma
# ──────────────────────────────────────────────────────────────
def export_html_report(scan_id: str):
    from pathlib import Path
    filename = f"pulse_report_{scan_id[:8]}.html"
    save_path = Path.home() / "Desktop" / filename
    try:
        res = httpx.get(f"{API_BASE_URL}/{scan_id}/report", headers=get_headers(), timeout=30.0)
        res.raise_for_status()
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(res.content)
        console.print(f"[bold green]✔ Rapor kaydedildi: {save_path}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Rapor oluşturulamadı: {e}[/bold red]")
    time.sleep(2)


# ──────────────────────────────────────────────────────────────
# Sayfalı zafiyet listesi
# ──────────────────────────────────────────────────────────────
def show_scan_details(scan_id: str, repo_url: str = "", skip_ai: bool = False):
    try:
        res = httpx.get(f"{API_BASE_URL}/{scan_id}/results", headers=get_headers(), timeout=15.0)
        res.raise_for_status()
        results = res.json()
    except Exception as e:
        clear_screen()
        render_header()
        console.print(f"[bold red][!] Sonuçlar alınamadı: {e}[/bold red]")
        time.sleep(3)
        return

    vulns = results.get("vulnerabilities", [])

    if not vulns:
        clear_screen()
        render_header()
        console.print("\n[bold green]✔ Bu taramada hiçbir güvenlik zafiyeti bulunamadı.[/bold green]")
        Prompt.ask("\nPress Enter to return")
        return

    page = 0
    total_pages = max(1, (len(vulns) + PAGE_SIZE - 1) // PAGE_SIZE)

    real_vulns = [v for v in vulns if not v.get("is_false_positive", False)]
    fp_count = len(vulns) - len(real_vulns)
    critical_count = sum(1 for v in real_vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in real_vulns if v.get("severity") == "HIGH")
    medium_count = sum(1 for v in real_vulns if v.get("severity") == "MEDIUM")

    while True:
        clear_screen()
        render_header()

        target_label = repo_url or scan_id[:8]
        console.print(f"[bold white]Scan:[/bold white] [cyan]{target_label}[/cyan]")
        fp_note = f"  [dim](+{fp_count} false positives excluded)[/dim]" if fp_count else ""
        console.print(
            f"[bold white]Findings:[/bold white] {len(real_vulns)} total{fp_note} — "
            f"[bold red]{critical_count} CRITICAL[/bold red]  "
            f"[red]{high_count} HIGH[/red]  "
            f"[yellow]{medium_count} MEDIUM[/yellow]"
        )
        console.print(f"[dim]Page {page + 1}/{total_pages}[/dim]\n")

        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(vulns))
        page_vulns = vulns[start:end]

        table = Table(
            box=box.DOUBLE_EDGE,
            border_style=MAGENTA,
            header_style="bold cyan",
            expand=False,
        )
        table.add_column("#", style="dim", min_width=3, justify="right", no_wrap=True)
        table.add_column("Type", style="cyan", min_width=8, no_wrap=True)
        table.add_column("Description", style="white", min_width=24, max_width=36, no_wrap=True)
        table.add_column("File", style="dim", min_width=20, max_width=40, no_wrap=True)
        table.add_column("Sev", justify="center", min_width=8, no_wrap=True)
        table.add_column("AI", justify="center", min_width=12, no_wrap=True)
        table.add_column("FP", justify="center", min_width=3, no_wrap=True)

        _TYPE_SHORT = {
            "dependency-vulnerability": "dep-vuln",
            "sast-finding": "sast",
            "secret": "secret",
        }

        def _summary(v: dict) -> str:
            import re
            vtype = v.get("vulnerability_type", "")
            desc = (v.get("description") or "").strip()
            vuln_id = (v.get("tool_vulnerability_id") or "").strip()

            if vtype == "dependency-vulnerability":
                m = re.match(r"Vulnerable package:\s*(\S+?)\.?\s", desc)
                if m:
                    return m.group(1)
                return vuln_id or desc[:30]

            # SAST / secret: strip noisy prefixes, take first meaningful line
            first = next(
                (ln.strip().lstrip("#").strip() for ln in desc.splitlines() if ln.strip().lstrip("#").strip()),
                vuln_id or desc,
            )
            short = re.sub(
                r"^(Detected |Possible |Found |By not specifying |Use of |A |An |The )",
                "", first, flags=re.IGNORECASE,
            )
            return short

        for i, v in enumerate(page_vulns, start=start + 1):
            sev = v.get("severity", "INFO")
            if sev == "CRITICAL":
                sev_fmt = "[bold red]CRITICAL[/bold red]"
            elif sev == "HIGH":
                sev_fmt = "[red]HIGH[/red]"
            elif sev == "MEDIUM":
                sev_fmt = "[yellow]MEDIUM[/yellow]"
            else:
                sev_fmt = f"[dim]{sev}[/dim]"

            has_ai = len(v.get("remediations", [])) > 0
            if skip_ai:
                ai_text = "[dim]Disabled[/dim]"
            elif has_ai:
                ai_text = "[bold green]✔ Ready[/bold green]"
            else:
                ai_text = "[bold yellow]⏳ Pending[/bold yellow]"

            fp_text = "[bold red]FP[/bold red]" if v.get("is_false_positive") else ""

            vtype = v.get("vulnerability_type", "N/A")
            type_short = _TYPE_SHORT.get(vtype, vtype[:8])

            summary = _summary(v)
            desc_cell = summary[:34] + "…" if len(summary) > 34 else summary

            line = v.get("line_number")
            file_path = v.get("file_path", "")
            file_cell = f"{file_path}:{line}" if line else file_path

            table.add_row(
                str(i),
                type_short,
                desc_cell,
                file_cell,
                sev_fmt,
                ai_text,
                fp_text,
            )

        console.print(table)

        nav_parts = []
        if page > 0:
            nav_parts.append("[P]rev")
        if page < total_pages - 1:
            nav_parts.append("[N]ext")
        nav_parts.append("[#] AI detayı")
        nav_parts.append("[D]iff")
        nav_parts.append("[E]xport HTML")
        nav_parts.append("[Q]uit")
        console.print(f"\n[dim]{' | '.join(nav_parts)}[/dim]")

        raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()

        if raw == "n" and page < total_pages - 1:
            page += 1
        elif raw == "p" and page > 0:
            page -= 1
        elif raw in ("q", ""):
            break
        elif raw == "d":
            show_diff_view(scan_id)
        elif raw == "e":
            export_html_report(scan_id)
        elif raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(vulns):
                show_vuln_ai_detail(vulns[idx], scan_id)
                # Re-fetch after potential FP toggle
                try:
                    res2 = httpx.get(f"{API_BASE_URL}/{scan_id}/results", headers=get_headers(), timeout=15.0)
                    if res2.status_code == 200:
                        vulns = res2.json().get("vulnerabilities", [])
                        total_pages = max(1, (len(vulns) + PAGE_SIZE - 1) // PAGE_SIZE)
                        page = min(page, total_pages - 1)
                except Exception:
                    pass
            else:
                console.print(f"[red]Geçersiz numara. 1-{len(vulns)} arası girin.[/red]")
                time.sleep(1)
        else:
            console.print("[dim red]Geçersiz komut.[/dim red]")
            time.sleep(0.8)


# ──────────────────────────────────────────────────────────────
# Tarama akışı
# ──────────────────────────────────────────────────────────────
def run_scan_flow(repo_url: str, skip_ai: bool = False):
    clear_screen()
    render_header()
    console.print(f"[bold white]Target:[/bold white] [cyan]{repo_url}[/cyan]")
    console.print(f"[bold white]Mode:[/bold white] [magenta]{'Quick' if skip_ai else 'Full'} Scan[/magenta]")
    console.print()

    try:
        response = httpx.post(
            f"{API_BASE_URL}/",
            json={"repo_url": repo_url, "skip_ai": skip_ai},
            headers=get_headers(),
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
        scan_id = data.get("scan_id")
    except (httpx.ConnectError, httpx.ConnectTimeout):
        console.print("\n[bold red][!] Sunucuya bağlanılamadı. Docker servislerinin çalıştığından emin olun.[/bold red]")
        time.sleep(4)
        return
    except Exception as e:
        console.print(f"\n[bold red][!] API Hatası: {str(e)}[/bold red]")
        time.sleep(3)
        return

    MAX_POLL_SECONDS = 300
    vuln_count = 0

    PHASE_MSGS = {
        "PENDING":  "[bold yellow]⏳ Kuyrukta bekleniyor...[/bold yellow]",
        "RUNNING":  "[bold cyan]🔍 Tarama devam ediyor...[/bold cyan]",
        "COMPLETED": "[bold green]✔ Tamamlandı[/bold green]",
        "FAILED":   "[bold red]✘ Hata[/bold red]",
    }

    with console.status(PHASE_MSGS["PENDING"], spinner="dots") as status_ctx:
        elapsed = 0
        while elapsed < MAX_POLL_SECONDS:
            try:
                res = httpx.get(f"{API_BASE_URL}/{scan_id}", headers=get_headers(), timeout=5.0)
                res.raise_for_status()
                status_data = res.json()
                db_status = status_data.get("status", "PENDING")
                vuln_count = status_data.get("vuln_count", 0)

                phase_msg = PHASE_MSGS.get(db_status, PHASE_MSGS["PENDING"])
                if elapsed > 0:
                    status_ctx.update(f"{phase_msg}  [dim]({elapsed}s)[/dim]")

                if db_status == "COMPLETED" or vuln_count > 0:
                    break
                elif db_status == "FAILED":
                    clear_screen()
                    render_header()
                    console.print(f"\n[bold red][!] Tarama Hatası:[/bold red] {status_data.get('logs', 'Unknown Error')}")
                    time.sleep(4)
                    return
            except Exception:
                break
            time.sleep(2)
            elapsed += 2
        else:
            clear_screen()
            render_header()
            console.print(f"\n[bold red][!] Zaman aşımı ({MAX_POLL_SECONDS}s). Tarama hâlâ devam ediyor olabilir.[/bold red]")
            time.sleep(4)
            return

    if vuln_count == 0:
        clear_screen()
        render_header()
        console.print("\n[bold green]✔ Tebrikler! Herhangi bir güvenlik zafiyeti bulunamadı.[/bold green]")
        Prompt.ask("\nPress Enter to return to menu")
        return

    if not skip_ai:
        clear_screen()
        render_header()
        console.print(
            f"\n[bold green]✔ Tarama tamamlandı — {vuln_count} zafiyet bulundu.[/bold green]\n"
            "[dim]AI enrichment arka planda devam ediyor. Sonuçları aşağıda görebilirsiniz.[/dim]\n"
        )
        time.sleep(1)

    show_scan_details(scan_id, repo_url=repo_url, skip_ai=skip_ai)


# ──────────────────────────────────────────────────────────────
# Geçmiş taramalar
# ──────────────────────────────────────────────────────────────
def show_history():
    while True:
        clear_screen()
        render_header()

        try:
            response = httpx.get(f"{API_BASE_URL}/all", headers=get_headers(), timeout=10.0)
            response.raise_for_status()
            history = response.json()
        except (httpx.ConnectError, httpx.ConnectTimeout):
            console.print("\n[bold red][!] Sunucuya bağlanılamadı.[/bold red]")
            time.sleep(4)
            return
        except Exception as e:
            console.print(f"[bold red][!] Hata: {e}[/bold red]")
            time.sleep(3)
            return

        if not history:
            console.print("\n[bold yellow]ℹ Henüz geçmiş tarama bulunamadı.[/bold yellow]")
            Prompt.ask("\nPress Enter to return to menu")
            return

        table = Table(
            title="[bold white]Scan History[/bold white]",
            box=box.ROUNDED,
            border_style=MAGENTA,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Repository", style="white")
        table.add_column("Status", justify="center", width=11)
        table.add_column("Findings", justify="center", width=9)
        table.add_column("Date", style="dim", width=17)

        for idx, item in enumerate(history, 1):
            status_style = "green" if item["status"] == "COMPLETED" else "red"
            started = item.get("started_at") or ""
            table.add_row(
                str(idx),
                item["id"][:8],
                item["repo_url"],
                f"[{status_style}]{item['status']}[/{status_style}]",
                str(item["vuln_count"]),
                started[:16].replace("T", " ") if started else "N/A",
            )

        console.print(table)
        console.print("\n[dim]Detay görmek için numara girin | [Q]uit[/dim]")
        raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()

        if raw in ("q", ""):
            return
        elif raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(history):
                item = history[idx]
                if item["status"] != "COMPLETED":
                    console.print(f"[bold yellow]Bu tarama {item['status']} durumunda, detay gösterilemiyor.[/bold yellow]")
                    time.sleep(2)
                    continue
                show_scan_details(item["id"], repo_url=item["repo_url"])
            else:
                console.print(f"[red]Geçersiz numara. 1-{len(history)} arası girin.[/red]")
                time.sleep(1)
        else:
            console.print("[dim red]Geçersiz komut.[/dim red]")
            time.sleep(0.8)


# ──────────────────────────────────────────────────────────────
# Schedule oluşturma akışı
# ──────────────────────────────────────────────────────────────
def create_schedule_flow():
    clear_screen()
    render_header()
    console.print("[bold cyan]Create Scheduled Scan[/bold cyan]\n")

    while True:
        source = console.input("[bold cyan]❯ GitHub URL or Local Path: [/bold cyan]").strip()
        if validate_source(source):
            break
        console.print("[bold red]Geçersiz kaynak.[/bold red]")

    console.print("\n[dim]Cron expressions — examples:[/dim]")
    console.print("[dim]  0 2 * * *   → daily at 02:00 UTC[/dim]")
    console.print("[dim]  0 * * * *   → every hour[/dim]")
    console.print("[dim]  */30 * * * * → every 30 minutes[/dim]\n")
    cron_expr = console.input("[bold cyan]❯ Cron expression: [/bold cyan]").strip()

    skip_ai_raw = console.input("[bold cyan]❯ Skip AI? [y/N]: [/bold cyan]").strip().lower()
    skip_ai = skip_ai_raw == "y"

    # First get or create the project to get its ID
    try:
        # Create a scan to get the project created, then immediately get its ID
        # Use a dedicated endpoint or just create schedule directly via API
        res = httpx.post(
            f"{SCHEDULES_API_URL}/",
            json={"repo_url": source, "cron_expression": cron_expr, "skip_ai": skip_ai},
            headers=get_headers(),
            timeout=10.0,
        )
        if res.status_code in (200, 201):
            data = res.json()
            nxt = data.get("next_run_at", "N/A")
            if nxt and nxt != "N/A":
                nxt = nxt[:16].replace("T", " ")
            console.print(f"\n[bold green]✔ Schedule oluşturuldu.[/bold green]  Next run: {nxt}")
        elif res.status_code == 422:
            detail = res.json().get("detail", "Invalid cron expression.")
            console.print(f"\n[bold red]Hata: {detail}[/bold red]")
        else:
            console.print(f"\n[bold red]API hatası ({res.status_code}): {res.text}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]İstek başarısız: {e}[/bold red]")
    time.sleep(3)


# ──────────────────────────────────────────────────────────────
# Schedule listesi & yönetimi
# ──────────────────────────────────────────────────────────────
def show_schedules():
    while True:
        clear_screen()
        render_header()

        try:
            res = httpx.get(f"{SCHEDULES_API_URL}/", headers=get_headers(), timeout=10.0)
            res.raise_for_status()
            schedules = res.json()
        except (httpx.ConnectError, httpx.ConnectTimeout):
            console.print("\n[bold red][!] Sunucuya bağlanılamadı.[/bold red]")
            time.sleep(4)
            return
        except Exception as e:
            console.print(f"[bold red][!] Hata: {e}[/bold red]")
            time.sleep(3)
            return

        if not schedules:
            console.print("\n[bold yellow]ℹ Henüz zamanlanmış tarama yok.[/bold yellow]")
            console.print("\n[dim][C]reate | [Q]uit[/dim]")
            raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()
            if raw == "c":
                create_schedule_flow()
            else:
                return
            continue

        table = Table(
            title="[bold white]Scheduled Scans[/bold white]",
            box=box.ROUNDED,
            border_style=MAGENTA,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Repository", style="white")
        table.add_column("Cron", style="cyan", width=14)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Next Run", style="dim", width=17)
        table.add_column("Runs", justify="center", width=5)

        for idx, s in enumerate(schedules, 1):
            status = s.get("status", "ACTIVE")
            status_style = "green" if status == "ACTIVE" else "red" if status == "ERROR" else "yellow"
            nxt = s.get("next_run_at", "") or ""
            table.add_row(
                str(idx),
                s["id"][:8],
                s.get("repo_url", s.get("project_id", "N/A")),
                s.get("cron_expression", "N/A"),
                f"[{status_style}]{status}[/{status_style}]",
                nxt[:16].replace("T", " ") if nxt else "N/A",
                str(s.get("run_count", 0)),
            )

        console.print(table)
        console.print("\n[dim][C]reate | [P]ause # | [R]esume # | [D]elete # | [T]rigger # | [Q]uit[/dim]")
        raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()

        if raw in ("q", ""):
            return
        elif raw == "c":
            create_schedule_flow()
        elif raw.startswith(("p", "r", "d", "t")) and len(raw) > 1:
            cmd = raw[0]
            num = raw[1:].strip()
            if not num.isdigit():
                console.print("[red]Format: p1, r2, d3, t4[/red]"); time.sleep(1); continue
            idx = int(num) - 1
            if not (0 <= idx < len(schedules)):
                console.print("[red]Geçersiz numara.[/red]"); time.sleep(1); continue
            sched_id = schedules[idx]["id"]
            try:
                if cmd == "d":
                    r = httpx.delete(f"{SCHEDULES_API_URL}/{sched_id}", headers=get_headers(), timeout=10.0)
                    console.print("[bold green]✔ Silindi.[/bold green]" if r.status_code == 204 else f"[red]{r.text}[/red]")
                elif cmd == "t":
                    r = httpx.post(f"{SCHEDULES_API_URL}/{sched_id}/run", headers=get_headers(), timeout=10.0)
                    console.print("[bold green]✔ Tetiklendi.[/bold green]" if r.status_code == 202 else f"[red]{r.text}[/red]")
                elif cmd == "p":
                    r = httpx.patch(f"{SCHEDULES_API_URL}/{sched_id}", json={"status": "PAUSED"}, headers=get_headers(), timeout=10.0)
                    console.print("[bold yellow]⏸ Duraklatıldı.[/bold yellow]" if r.status_code == 200 else f"[red]{r.text}[/red]")
                elif cmd == "r":
                    r = httpx.patch(f"{SCHEDULES_API_URL}/{sched_id}", json={"status": "ACTIVE"}, headers=get_headers(), timeout=10.0)
                    console.print("[bold green]▶ Devam ettirild.[/bold green]" if r.status_code == 200 else f"[red]{r.text}[/red]")
            except Exception as e:
                console.print(f"[bold red]Hata: {e}[/bold red]")
            time.sleep(1.5)
        else:
            console.print("[dim red]Geçersiz komut.[/dim red]")
            time.sleep(0.8)


# ──────────────────────────────────────────────────────────────
# Yardım ekranı
# ──────────────────────────────────────────────────────────────
def show_help():
    clear_screen()
    render_header()

    cap_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    cap_table.add_column("Icon", justify="center", width=4)
    cap_table.add_column("Feature", style="bold white", width=24)
    cap_table.add_column("Description", style="white")

    cap_table.add_row("[bold magenta]⚡[/bold magenta]", "Secrets Scanning",
                      "Gitleaks ile 400+ regex kuralı — API key, token, parola tespiti.")
    cap_table.add_row("[bold cyan]🔎[/bold cyan]", "SAST (Semgrep)",
                      "Kod seviyesinde güvenlik açıkları — SQLi, XSS, hardcoded secrets.")
    cap_table.add_row("[bold blue]📦[/bold blue]", "Dependency Audit",
                      "pip-audit ile Python bağımlılıklarındaki bilinen CVE'ler.")
    cap_table.add_row("[bold yellow]🧠[/bold yellow]", "AI Remediation",
                      "Llama3/GPT-4o ile otomatik düzeltme önerisi + kod bağlamı.")
    cap_table.add_row("[bold green]📄[/bold green]", "HTML Report",
                      "Detaylı HTML raporu — Scan listesinden [E] ile indirin.")
    cap_table.add_row("[bold red]🔀[/bold red]", "Scan Diff",
                      "İki tarama arası fark — yeni / düzeltilmiş / kalıcı bulgular.")
    cap_table.add_row("[bold white]🚩[/bold white]", "False Positives",
                      "Zafiyet detayında [F] ile yanlış alarm olarak işaretle.")
    cap_table.add_row("[bold magenta]⏰[/bold magenta]", "Scheduled Scans",
                      "Cron tabanlı otomatik tarama — menüden [4] ile yönet.")

    console.print(Panel(cap_table, title="[bold cyan]  V2 Yetenekleri[/bold cyan]", border_style=CYAN, padding=(1, 2)))
    console.print()

    flow_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    flow_table.add_column("Step", justify="right", style="bold cyan", width=6)
    flow_table.add_column("Action", style="white")

    flow_table.add_row("1", "[bold white]Tarama başlat:[/bold white] [bold cyan][1][/bold cyan] Full veya [bold cyan][2][/bold cyan] Quick.")
    flow_table.add_row("2", "[bold white]Kaynak:[/bold white] GitHub URL veya yerel dizin yolu.")
    flow_table.add_row("3", "[bold white]Sonuçlar:[/bold white] Sayfalı zafiyet listesi — FP'ler ayrı gösterilir.")
    flow_table.add_row("4", "[bold white]AI detayı:[/bold white] [bold cyan]numara[/bold cyan] → AI analizi, [bold cyan][F][/bold cyan] → false positive işaretle.")
    flow_table.add_row("5", "[bold white]Diff:[/bold white] [bold cyan][D][/bold cyan] → önceki taramayla karşılaştır.")
    flow_table.add_row("6", "[bold white]Rapor:[/bold white] [bold cyan][E][/bold cyan] → HTML raporu dışa aktar.")

    console.print(Panel(flow_table, title="[bold magenta]  Kullanim Akisi[/bold magenta]", border_style=MAGENTA, padding=(1, 2)))
    console.print()

    nav_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    nav_table.add_column("Key", style="bold cyan", width=12)
    nav_table.add_column("Action", style="white")

    nav_table.add_row("[N] / [P]", "Sonraki / Önceki sayfa")
    nav_table.add_row("[1-99]", "O zafiyetin AI analizini aç")
    nav_table.add_row("[F] / [U]", "False positive işaretle / geri al (detay ekranında)")
    nav_table.add_row("[D]", "Diff — önceki taramayla karşılaştır")
    nav_table.add_row("[E]", "HTML raporu dışa aktar")
    nav_table.add_row("[Q]", "Geri dön / çık")

    console.print(Panel(nav_table, title="[bold green]  Navigasyon[/bold green]", border_style="green", padding=(1, 2)))
    console.print()

    env_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    env_table.add_column("Variable", style="bold cyan", width=20)
    env_table.add_column("Purpose", style="white")

    env_table.add_row("PULSE_API_KEY", "API güvenlik anahtarı (boşsa dev modu)")
    env_table.add_row("WEBHOOK_URL", "Slack/Teams/custom webhook URL'si")
    env_table.add_row("OLLAMA_BASE_URL", "Ollama endpoint (varsayılan: localhost:11434)")
    env_table.add_row("AI_MODEL", "LLM modeli (llama3 veya gpt-4o)")

    console.print(Panel(env_table, title="[bold yellow]  Ortam Degiskenleri[/bold yellow]", border_style="yellow", padding=(1, 2)))

    Prompt.ask("\n[dim]Press Enter to return to main menu[/dim]")


# ──────────────────────────────────────────────────────────────
# Ana menü
# ──────────────────────────────────────────────────────────────
def show_menu():
    menu_content = Text()
    menu_content.append("\n")
    menu_content.append("[1] ", style=CYAN)
    menu_content.append("Full Scan  (Gitleaks + Semgrep + pip-audit + AI)\n", style=WHITE)
    menu_content.append("[2] ", style=CYAN)
    menu_content.append("Quick Scan (No AI)\n", style=WHITE)
    menu_content.append("[3] ", style=CYAN)
    menu_content.append("View Past Scans (History)\n", style=WHITE)
    menu_content.append("[4] ", style=CYAN)
    menu_content.append("Scheduled Scans\n", style=WHITE)
    menu_content.append("[5] ", style=CYAN)
    menu_content.append("Help\n", style=WHITE)
    menu_content.append("[6] ", style=CYAN)
    menu_content.append("Quit\n", style=WHITE)

    console.print(Align.center(Panel(
        menu_content,
        title="[bold magenta]Interactive Menu[/bold magenta]",
        border_style=MAGENTA,
        box=box.ROUNDED,
        width=64,
        padding=(0, 2),
    )))


@app.callback(invoke_without_command=True)
def main():
    while True:
        clear_screen()
        render_header()
        show_menu()

        while True:
            choice = console.input("[bold magenta]pulse [bold green]❯: [/bold green][/bold magenta]")
            if choice in ["1", "2", "3", "4", "5", "6"]:
                break
            console.print("[dim red]Invalid choice. Please select 1-6.[/dim red]")

        if choice == "6":
            console.print("[bold magenta]Goodbye![/bold magenta]")
            break
        if choice == "5":
            show_help()
            continue
        if choice == "4":
            show_schedules()
            continue

        clear_screen()
        render_header()

        if choice in ["1", "2"]:
            skip_ai = choice == "2"
            while True:
                source = console.input("[bold cyan]❯ Enter GitHub URL or Local Path: [/bold cyan]")
                if not validate_source(source):
                    console.print("[bold red][!] Geçersiz kaynak! GitHub URL'si veya geçerli bir dizin yolu girin.[/bold red]")
                    continue

                # Warn if same repo was scanned recently
                try:
                    from datetime import datetime, timezone as _tz
                    hist_r = httpx.get(f"{API_BASE_URL}/all", headers=get_headers(), timeout=5.0)
                    if hist_r.status_code == 200:
                        recent = [
                            s for s in hist_r.json()
                            if s.get("repo_url") == source and s.get("status") == "COMPLETED"
                        ]
                        if recent:
                            last = recent[0]
                            started = last.get("started_at") or ""
                            if started:
                                last_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                                age_min = (datetime.now(_tz.utc) - last_dt).total_seconds() / 60
                                if age_min < 60:
                                    console.print(
                                        f"[bold yellow]⚠  Bu repo {age_min:.0f} dakika önce tarandı "
                                        f"({last.get('vuln_count', 0)} bulgu). Yeniden taranacak.(Y/N)[/bold yellow]"
                                    )
                                    confirm = console.input("[bold cyan]❯ Devam et? [y/N]: [/bold cyan]").strip().lower()
                                    if confirm != "y":
                                        break
                except Exception:
                    pass

                run_scan_flow(source, skip_ai=skip_ai)
                break
        elif choice == "3":
            show_history()


if __name__ == "__main__":
    app()
