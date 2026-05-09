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
VERSION = "1.0.0 [STABLE]"
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
# AI Detay Ekranı — tek bir zafiyetin AI önerisini göster
# ──────────────────────────────────────────────────────────────
def show_vuln_ai_detail(vuln: dict):
    clear_screen()
    render_header()

    sev = vuln.get("severity", "INFO")
    sev_style = "bold red" if sev in ["CRITICAL", "HIGH"] else "bold yellow"

    info = (
        f"[bold white]Type:[/bold white]        {vuln.get('vulnerability_type', 'N/A')}\n"
        f"[bold white]File:[/bold white]        {vuln.get('file_path', 'N/A')}:{vuln.get('line_number', '')}\n"
        f"[bold white]Severity:[/bold white]    [{sev_style}]{sev}[/{sev_style}]\n"
        f"[bold white]Description:[/bold white] {vuln.get('description', 'N/A')}"
    )
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

    Prompt.ask("\n[dim]Press Enter to return[/dim]")


# ──────────────────────────────────────────────────────────────
# Sayfalı zafiyet listesi — hem scan sonucu hem history drill-down kullanır
# ──────────────────────────────────────────────────────────────
def show_scan_details(scan_id: str, repo_url: str = "", skip_ai: bool = False):
    try:
        res = httpx.get(f"{API_BASE_URL}/{scan_id}/results", timeout=15.0)
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

    # Sayfalama döngüsü
    page = 0
    total_pages = max(1, (len(vulns) + PAGE_SIZE - 1) // PAGE_SIZE)

    critical_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")

    while True:
        clear_screen()
        render_header()

        # Özet başlık
        target_label = repo_url or scan_id[:8]
        console.print(f"[bold white]Scan:[/bold white] [cyan]{target_label}[/cyan]")
        console.print(
            f"[bold white]Findings:[/bold white] {len(vulns)} total — "
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
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Type", style="cyan", min_width=12)
        table.add_column("File", style="white")
        table.add_column("Sev", justify="center", width=10)
        table.add_column("AI", justify="center", width=14)

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

            table.add_row(
                str(i),
                v.get("vulnerability_type", "N/A"),
                f"{v.get('file_path', '')}:{v.get('line_number', '')}",
                sev_fmt,
                ai_text,
            )

        console.print(table)

        # Navigasyon ipuçları
        nav_parts = []
        if page > 0:
            nav_parts.append("[P]rev")
        if page < total_pages - 1:
            nav_parts.append("[N]ext")
        nav_parts.append("[#] AI detayı")
        nav_parts.append("[Q]uit")
        console.print(f"\n[dim]{' | '.join(nav_parts)}[/dim]")

        raw = console.input("[bold magenta]❯ [/bold magenta]").strip().lower()

        if raw == "n" and page < total_pages - 1:
            page += 1
        elif raw == "p" and page > 0:
            page -= 1
        elif raw in ("q", ""):
            break
        elif raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(vulns):
                show_vuln_ai_detail(vulns[idx])
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

    # Polling — duruma göre spinner mesajı güncellenir
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
                res = httpx.get(f"{API_BASE_URL}/{scan_id}", timeout=5.0)
                res.raise_for_status()
                status_data = res.json()
                db_status = status_data.get("status", "PENDING")
                vuln_count = status_data.get("vuln_count", 0)

                # Spinner metnini fase göre güncelle
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
# Geçmiş taramalar — drill-down ile AI analizi
# ──────────────────────────────────────────────────────────────
def show_history():
    while True:
        clear_screen()
        render_header()

        try:
            response = httpx.get(f"{API_BASE_URL}/all", timeout=10.0)
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
# Yardım ekranı
# ──────────────────────────────────────────────────────────────
def show_help():
    clear_screen()
    render_header()

    # ── Yetenekler ──────────────────────────────────────────
    cap_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    cap_table.add_column("Icon", justify="center", width=4)
    cap_table.add_column("Feature", style="bold white", width=22)
    cap_table.add_column("Description", style="white")

    cap_table.add_row(
        "[bold magenta]⚡[/bold magenta]",
        "Secrets Scanning",
        "Gitleaks ile 400+ regex kuralı — API anahtarları, token'lar, parolalar.",
    )
    cap_table.add_row(
        "[bold cyan]📦[/bold cyan]",
        "Dependency Audit",
        "pip-audit ile Python bağımlılıklarındaki bilinen CVE'leri tespit eder.",
    )
    cap_table.add_row(
        "[bold yellow]🧠[/bold yellow]",
        "AI Remediation",
        "Her benzersiz zafiyet tipi için Ollama/Llama3 ile otomatik düzeltme önerisi.",
    )
    cap_table.add_row(
        "[bold green]📄[/bold green]",
        "History & Drill-Down",
        "Geçmiş taramaları listele, istediğin scan'a girip AI analizini görüntüle.",
    )
    cap_table.add_row(
        "[bold blue]⚡[/bold blue]",
        "Fire-and-Forget",
        "Tarama anında kuyruğa alınır, API bloke olmaz; sonuçlar DB'ye yazılır.",
    )

    console.print(Panel(
        cap_table,
        title="[bold cyan]  Sistem Yetenekleri[/bold cyan]",
        border_style=CYAN,
        padding=(1, 2),
    ))
    console.print()

    # ── Kullanım Akışı ───────────────────────────────────────
    flow_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    flow_table.add_column("Step", justify="right", style="bold cyan", width=6)
    flow_table.add_column("Action", style="white")

    flow_table.add_row("1", "[bold white]Tarama başlat:[/bold white] Menüden [bold cyan][1][/bold cyan] Full veya [bold cyan][2][/bold cyan] Quick seç.")
    flow_table.add_row("2", "[bold white]Kaynak gir:[/bold white] GitHub URL'si (https://github.com/org/repo) veya yerel dizin yolu.")
    flow_table.add_row("3", "[bold white]Sonuçlar:[/bold white] Tarama biter bitmez sayfalı zafiyet listesi açılır.")
    flow_table.add_row("4", "[bold white]AI detayı:[/bold white] Listeden bir [bold cyan]numara[/bold cyan] yaz → o zafiyetin AI analizi ve kod önerisi.")
    flow_table.add_row("5", "[bold white]History:[/bold white] Menüden [bold cyan][3][/bold cyan] → geçmiş tarama seç → aynı drill-down akışı.")

    console.print(Panel(
        flow_table,
        title="[bold magenta]  Kullanim Akisi[/bold magenta]",
        border_style=MAGENTA,
        padding=(1, 2),
    ))
    console.print()

    # ── Navigasyon Kısayolları ────────────────────────────────
    nav_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    nav_table.add_column("Key", style="bold cyan", width=10)
    nav_table.add_column("Action", style="white")

    nav_table.add_row("[N]", "Sonraki sayfa  (zafiyet listesi)")
    nav_table.add_row("[P]", "Önceki sayfa   (zafiyet listesi)")
    nav_table.add_row("[1-99]", "O numaralı zafiyetin AI analizini aç")
    nav_table.add_row("[Q]", "Geri dön / çık")

    console.print(Panel(
        nav_table,
        title="[bold green]  Navigasyon[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))
    console.print()

    # ── Scan Modları ──────────────────────────────────────────
    mode_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    mode_table.add_column("Mode", style="bold white", width=14)
    mode_table.add_column("Description", style="white")

    mode_table.add_row(
        "[bold magenta]Full Scan[/bold magenta]",
        "Gitleaks + pip-audit + AI remediation. Arka planda AI analizi devam eder.",
    )
    mode_table.add_row(
        "[bold cyan]Quick Scan[/bold cyan]",
        "Gitleaks + pip-audit, AI analizi yok. Sonuçlar anında hazır.",
    )

    console.print(Panel(
        mode_table,
        title="[bold yellow]  Tarama Modlari[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
    ))

    Prompt.ask("\n[dim]Press Enter to return to main menu[/dim]")


# ──────────────────────────────────────────────────────────────
# Ana menü
# ──────────────────────────────────────────────────────────────
def show_menu():
    menu_content = Text()
    menu_content.append("\n")
    menu_content.append("[1] ", style=CYAN)
    menu_content.append("Full Scan (Secrets + Libraries + AI)\n", style=WHITE)
    menu_content.append("[2] ", style=CYAN)
    menu_content.append("Quick Scan (No AI)\n", style=WHITE)
    menu_content.append("[3] ", style=CYAN)
    menu_content.append("View Past Scans (History)\n", style=WHITE)
    menu_content.append("[4] ", style=CYAN)
    menu_content.append("Help\n", style=WHITE)
    menu_content.append("[5] ", style=CYAN)
    menu_content.append("Quit\n", style=WHITE)

    console.print(Align.center(Panel(
        menu_content,
        title="[bold magenta]Interactive Menu[/bold magenta]",
        border_style=MAGENTA,
        box=box.ROUNDED,
        width=60,
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
            if choice in ["1", "2", "3", "4", "5"]:
                break
            console.print("[dim red]Invalid choice. Please select 1-5.[/dim red]")

        if choice == "5":
            console.print("[bold magenta]Goodbye![/bold magenta]")
            break
        if choice == "4":
            show_help()
            continue

        clear_screen()
        render_header()

        if choice in ["1", "2"]:
            skip_ai = choice == "2"
            while True:
                source = console.input("[bold cyan]❯ Enter GitHub URL or Local Path: [/bold cyan]")
                if validate_source(source):
                    run_scan_flow(source, skip_ai=skip_ai)
                    break
                console.print("[bold red][!] Geçersiz kaynak! GitHub URL'si veya geçerli bir dizin yolu girin.[/bold red]")
        elif choice == "3":
            show_history()


if __name__ == "__main__":
    app()
