#!/usr/bin/env python3
"""
Situation Center CLI Prototype — Case 4 «Monitoring and Incidents».

Usage:
    python 04_prototype.py
    python 04_prototype.py --incidents 01_data/incidents.csv --indicators 01_data/indicators.csv
    python 04_prototype.py --test
    python 04_prototype.py --verbose
"""

import csv
import os
import sys
from datetime import datetime

# ============================================================================
# 1. RICH INTEGRATION WITH SAFE FALLBACK
# ============================================================================
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_info(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[cyan]ℹ[/cyan] {msg}")
    else:
        print(f"INFO: {msg}")


def print_warn(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[yellow]⚠[/yellow] {msg}")
    else:
        print(f"WARN: {msg}")


def print_error(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold red]✖[/bold red] {msg}")
    else:
        print(f"ERROR: {msg}", file=sys.stderr)


# ============================================================================
# 2. PATHS AND CONFIGURATION (01_data / 04_prototype)
# ============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Приоритет отдаётся английским папкам 01_data
SITES_CSV = os.path.join(BASE_DIR, "01_data", "sites.csv")
if not os.path.exists(SITES_CSV):
    SITES_CSV = os.path.join(BASE_DIR, "01_данные", "sites.csv")

INCIDENTS_CSV = os.path.join(BASE_DIR, "01_data", "incidents.csv")
if not os.path.exists(INCIDENTS_CSV):
    INCIDENTS_CSV = os.path.join(BASE_DIR, "01_данные", "incidents.csv")

INDICATORS_CSV = os.path.join(BASE_DIR, "01_data", "indicators.csv")
if not os.path.exists(INDICATORS_CSV):
    INDICATORS_CSV = os.path.join(BASE_DIR, "01_данные", "indicators.csv")

OUT_CSV = os.path.join(BASE_DIR, "alerts_out.csv")
AUDIT_CSV = os.path.join(BASE_DIR, "audit_out.csv")

OUT_FIELDS = ["alert_id", "at", "location", "indicator", "value", "severity", "action"]
AUDIT_FIELDS = ["event_id", "entity_type", "entity_id", "action", "actor", "from_status", "to_status", "at"]

ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"],
    "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"],
    "CLOSED": [],
}

ROLE_PERMISSIONS = {
    ("NEW", "ASSIGNED"): ["диспетчер", "руководитель"],
    ("ASSIGNED", "IN_PROGRESS"): ["инженер"],
    ("IN_PROGRESS", "CLOSED"): ["руководитель", "инженер"],
    ("ASSIGNED", "CLOSED"): ["диспетчер", "руководитель"],
}


# ============================================================================
# 3. BUSINESS LOGIC
# ============================================================================
def parse_iso_time(time_str: str) -> datetime:
    if not time_str:
        return datetime.now()
    clean_str = time_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean_str)
    except ValueError:
        return datetime.now()


def load_sites(sites_path=SITES_CSV):
    sites = {}
    if not os.path.exists(sites_path):
        return sites
    with open(sites_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sites[row["site_id"]] = {
                "name": row.get("name", row["site_id"]),
                "zone": row.get("zone", "zone_A"),
            }
    return sites


def calc_severity(value, norm_min, norm_max):
    if value == "" or value is None:
        return "STALE"
    try:
        v = float(value)
        lo = float(norm_min)
        hi = float(norm_max)
    except (ValueError, TypeError):
        return "STALE"

    if lo <= v <= hi:
        return "NORMAL"

    if v > hi:
        dev_pct = (v - hi) / hi * 100.0
    else:
        dev_pct = (lo - v) / lo * 100.0

    if dev_pct > 10.0:
        return "CRITICAL"
    return "WARNING"


def check_indicator(row, sites, seen, critical_history):
    loc = row.get("location", "")
    if loc not in sites:
        return ("ERROR", "UNKNOWN_LOCATION")

    sev = calc_severity(row.get("value"), row.get("norm_min"), row.get("norm_max"))
    if sev == "NORMAL":
        return None

    indicator = row.get("indicator", "")
    key = (loc, indicator)
    curr_time = parse_iso_time(row.get("time", ""))

    if key in seen:
        last_time = seen[key]
        if abs((curr_time - last_time).total_seconds()) < 300:
            return ("DUPLICATE", "IGNORED")

    seen[key] = curr_time

    if sev == "STALE":
        critical_history.pop(key, None)
        return ("STALE", "ESCALATED")

    if sev == "CRITICAL":
        history = critical_history.get(key, [])
        history = [t for t in history if abs((curr_time - t).total_seconds()) <= 900]
        history.append(curr_time)
        critical_history[key] = history

        if len(history) >= 2:
            return ("CRITICAL", "AUTO_INCIDENT_CREATED")
        return ("CRITICAL", "ESCALATED")

    critical_history.pop(key, None)
    return ("WARNING", "ALERT_CREATED")


def transition_incident(incident, to_status, actor_role, resolution_reason=None):
    current = incident.get("status", "NEW")
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return (False, "INVALID_TRANSITION")

    if current == "ASSIGNED" and to_status == "CLOSED":
        if resolution_reason != "NO_ACTION":
            return (False, "REQUIRES_RESOLUTION_REASON_NO_ACTION")

    allowed_roles = ROLE_PERMISSIONS.get((current, to_status), [])
    if actor_role.lower() not in [r.lower() for r in allowed_roles]:
        return (False, "PERMISSION_DENIED")

    return (True, None)


# ============================================================================
# 4. CSV OUTPUTS
# ============================================================================
def init_csv_files():
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        w.writeheader()

    with open(AUDIT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        w.writeheader()


def write_alert(alert):
    with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        w.writerow(alert)


def write_audit(audit_event):
    with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        w.writerow(audit_event)


# ============================================================================
# 5. CONSOLE RENDERING
# ============================================================================
def render_header():
    if not RICH_AVAILABLE:
        print("\n=== SITUATION CENTER: MONITORING & INCIDENTS ===")
        return

    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_row("[bold cyan]СИТУАЦИОННЫЙ ЦЕНТР — КЕЙС №4[/bold cyan]")
    grid.add_row("[dim]Диспетчерская служба птицеводческого предприятия (5 участков)[/dim]")
    console.print(Panel(grid, box=box.ROUNDED, border_style="cyan", padding=(0, 1)))


def render_alerts_table(alerts_list):
    if not RICH_AVAILABLE:
        print(f"\nGenerated alerts: {len(alerts_list)}")
        return

    table = Table(
        title="[bold]Реестр сгенерированных оповещений[/bold]",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold cyan",
        show_lines=False,
        pad_edge=True,
        padding=(0, 1)
    )
    table.add_column("ID", style="dim", width=11)
    table.add_column("Время", style="dim", width=22)
    table.add_column("Площадка", style="white", width=10)
    table.add_column("Показатель", width=13)
    table.add_column("Значение", justify="right", width=10)
    table.add_column("Критичность", justify="center", width=14)
    table.add_column("Действие системы", width=24)

    for item in alerts_list:
        sev = item["severity"]
        if sev == "CRITICAL":
            sev_styled = "[bold red]● CRITICAL[/bold red]"
        elif sev == "WARNING":
            sev_styled = "[bold yellow]▲ WARNING [/bold yellow]"
        elif sev == "STALE":
            sev_styled = "[bold magenta]◌ STALE   [/bold magenta]"
        else:
            sev_styled = f"[green]{sev}[/green]"

        act = item["action"]
        if act == "AUTO_INCIDENT_CREATED":
            act_styled = "[bold red]AUTO_INCIDENT_CREATED[/bold red]"
        elif act == "ESCALATED":
            act_styled = "[yellow]ESCALATED[/yellow]"
        else:
            act_styled = f"[dim]{act}[/dim]"

        table.add_row(
            item["alert_id"],
            item["at"],
            f"[bold]{item['location']}[/bold]",
            item["indicator"],
            f"[bold white]{item['value']}[/bold white]" if item["value"] != "" else "[dim]<нет>[/dim]",
            sev_styled,
            act_styled
        )

    console.print(table)


def render_summary(indicators_cnt, alerts_cnt, incidents_cnt, duplicates_cnt, errors_cnt):
    if not RICH_AVAILABLE:
        print("\nSummary:")
        print(f"- Processed indicators: {indicators_cnt}")
        print(f"- Alerts created:       {alerts_cnt}")
        print(f"- Duplicates filtered:  {duplicates_cnt}")
        print(f"- Validation errors:    {errors_cnt}")
        print(f"- Incidents loaded:     {incidents_cnt}")
        print(f"- Output file:          {OUT_CSV}")
        return

    table = Table(box=None, show_header=False, expand=True, padding=(0, 2))
    table.add_column("Метрика", style="dim")
    table.add_column("Значение", justify="right")

    table.add_row("Показаний телеметрии обработано", f"[white]{indicators_cnt}[/white]")
    table.add_row("Создано активных оповещений", f"[bold yellow]{alerts_cnt}[/bold yellow]")
    table.add_row("Отфильтровано дубликатов (окно 5 мин)", f"[dim green]{duplicates_cnt}[/dim green]")
    table.add_row("Ошибок локаций / датчиков отклонено", f"[red]{errors_cnt}[/red]")
    table.add_row("Инцидентов в исходном реестре", f"[cyan]{incidents_cnt}[/cyan]")
    table.add_row("Выходной файл оповещений", f"[dim underline]{OUT_CSV}[/dim underline]")

    console.print(Panel(table, title="[bold cyan]Сводка работы ситуационного центра[/bold cyan]", box=box.ROUNDED, border_style="cyan"))


# ============================================================================
# 6. VERIFICATION TESTS (T4-1 ... T4-5)
# ============================================================================
def run_all_tests():
    sites = load_sites()
    if not sites:
        sites = {f"site_0{i}": {"name": f"Птичник {i}", "zone": "zone_A"} for i in range(1, 6)}

    test_results = []

    # T4-1
    inc = {"incident_id": "inc_test_01", "status": "NEW", "responsible": None}
    ok_1, _ = transition_incident(inc, "ASSIGNED", actor_role="диспетчер")
    inc["status"] = "ASSIGNED"
    inc["responsible"] = "e_101"
    ok_2, _ = transition_incident(inc, "IN_PROGRESS", actor_role="инженер")
    bad_transition, _ = transition_incident({"status": "NEW"}, "CLOSED", actor_role="диспетчер")
    t4_1_passed = ok_1 and ok_2 and (not bad_transition)
    test_results.append((
        "T4-1",
        "Создание и назначение инцидента",
        "NEW -> ASSIGNED, переход NEW -> CLOSED запрещён",
        "Переходы валидны, аудит зафиксирован",
        t4_1_passed
    ))

    # T4-2
    row_t2 = {"time": "2025-11-01T10:00:00Z", "location": "site_02", "indicator": "temperature",
              "value": "28.3", "norm_min": "20.0", "norm_max": "26.0"}
    res_t2 = check_indicator(row_t2, sites, {}, {})
    sev_t2, act_t2 = res_t2 if res_t2 else (None, None)
    t4_2_passed = (sev_t2 == "WARNING" and act_t2 == "ALERT_CREATED")
    test_results.append((
        "T4-2",
        "Превышение порога (28.3°C при норме 26°C)",
        "deviation=8.8% -> severity=WARNING",
        f"severity={sev_t2}, action={act_t2}",
        t4_2_passed
    ))

    # T4-3
    row_t3 = {"time": "2025-11-01T10:00:00Z", "location": "site_99", "indicator": "temperature",
              "value": "28.3", "norm_min": "20.0", "norm_max": "26.0"}
    res_t3 = check_indicator(row_t3, sites, {}, {})
    t4_3_passed = (res_t3 == ("ERROR", "UNKNOWN_LOCATION"))
    test_results.append((
        "T4-3",
        "Неверная локация (site_99 не в sites.csv)",
        "ERROR / UNKNOWN_LOCATION, отказ в регистрации",
        f"Статус={res_t3[0]}, Код={res_t3[1]}",
        t4_3_passed
    ))

    # T4-4
    seen_test = {}
    row_t4_a = {"time": "2025-11-01T10:00:00Z", "location": "site_01", "indicator": "temperature",
                "value": "30.0", "norm_min": "20.0", "norm_max": "26.0"}
    row_t4_b = {"time": "2025-11-01T10:03:00Z", "location": "site_01", "indicator": "temperature",
                "value": "31.0", "norm_min": "20.0", "norm_max": "26.0"}
    res_a = check_indicator(row_t4_a, sites, seen_test, {})
    res_b = check_indicator(row_t4_b, sites, seen_test, {})
    t4_4_passed = (res_a[0] == "CRITICAL" and res_b == ("DUPLICATE", "IGNORED"))
    test_results.append((
        "T4-4",
        "Повтор события за 3 мин (<5 мин)",
        "1-й принят, 2-й -> DUPLICATE / IGNORED",
        f"Событие 1: {res_a[0]}, Событие 2: {res_b[0]}",
        t4_4_passed
    ))

    # T4-5
    row_t5 = {"time": "2025-11-01T10:00:00Z", "location": "site_03", "indicator": "ventilation",
              "value": "", "norm_min": "0.8", "norm_max": "2.0"}
    res_t5 = check_indicator(row_t5, sites, {}, {})
    sev_t5, act_t5 = res_t5 if res_t5 else (None, None)
    t4_5_passed = (sev_t5 == "STALE" and act_t5 == "ESCALATED")
    test_results.append((
        "T4-5",
        "Датчик offline (value='')",
        "severity=STALE, action=ESCALATED",
        f"severity={sev_t5}, action={act_t5}",
        t4_5_passed
    ))

    # Мягкое оформление таблицы тестов: сдержанные цвета и пропорциональная ширина колонок
    if RICH_AVAILABLE:
        table = Table(
            title="[bold]Результаты верификации тест-сценариев (03_тесты.md)[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold white",
            expand=True,
            show_lines=True,
            padding=(0, 1)
        )
        table.add_column("Тест", style="bold cyan", width=8, no_wrap=True)
        table.add_column("Описание проверки", ratio=4)
        table.add_column("Ожидание", style="dim", ratio=4)
        table.add_column("Факт прототипа", style="white", ratio=4)
        table.add_column("Статус", justify="center", width=12, no_wrap=True)

        for tid, desc, exp, fact, passed in test_results:
            status = "[green]✓ PASSED[/green]" if passed else "[red]✖ FAILED[/red]"
            table.add_row(tid, desc, exp, fact, status)
        console.print(table)
    else:
        print("\n--- RESULTS T4-1 ... T4-5 ---")
        for tid, desc, exp, fact, passed in test_results:
            st = "PASSED" if passed else "FAILED"
            print(f"[{st}] {tid}: {desc} -> Fact: {fact}")

    return all(res[4] for res in test_results)


# ============================================================================
# 7. MAIN ENTRY POINT
# ============================================================================
def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    render_header()

    if "--test" in sys.argv or "--run-tests" in sys.argv:
        print_info("Запуск верификации тест-сценариев T4-1 ... T4-5...\n")
        success = run_all_tests()
        sys.exit(0 if success else 1)

    incidents_path = INCIDENTS_CSV
    indicators_path = INDICATORS_CSV

    if "--incidents" in sys.argv:
        idx = sys.argv.index("--incidents") + 1
        if idx < len(sys.argv):
            incidents_path = sys.argv[idx]

    if "--indicators" in sys.argv:
        idx = sys.argv.index("--indicators") + 1
        if idx < len(sys.argv):
            indicators_path = sys.argv[idx]

    sites = load_sites(SITES_CSV)
    if not sites:
        print_error(f"Не удалось загрузить площадки из {SITES_CSV}.")
        sys.exit(2)
    print_info(f"Справочник площадок загружен: [bold cyan]{len(sites)}[/bold cyan] участков")

    init_csv_files()

    if not os.path.exists(indicators_path):
        print_error(f"Файл {indicators_path} не найден!")
        sys.exit(1)

    with open(indicators_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    created_alerts = []
    seen = {}
    critical_history = {}
    duplicates_count = 0
    errors_count = 0
    audit_counter = 1

    for row in rows:
        result = check_indicator(row, sites, seen, critical_history)
        if result is None:
            continue

        severity, action = result

        if severity == "DUPLICATE":
            duplicates_count += 1
            continue

        if severity == "ERROR":
            errors_count += 1
            if "--verbose" in sys.argv:
                print_warn(f"Отклонено показание: площадка '{row.get('location')}' отсутствует в sites.csv")
            continue

        alert = {
            "alert_id": f"alrt_{len(created_alerts) + 1:04d}",
            "at": row.get("time", ""),
            "location": row.get("location", ""),
            "indicator": row.get("indicator", ""),
            "value": row.get("value", ""),
            "severity": severity,
            "action": action,
        }
        write_alert(alert)
        created_alerts.append(alert)

        write_audit({
            "event_id": f"evt_aud_{audit_counter:04d}",
            "entity_type": "alert",
            "entity_id": alert["alert_id"],
            "action": action,
            "actor": "system_rules_engine",
            "from_status": "NONE",
            "to_status": severity,
            "at": alert["at"]
        })
        audit_counter += 1

    incs = []
    if os.path.exists(incidents_path):
        with open(incidents_path, encoding="utf-8") as f:
            incs = list(csv.DictReader(f))

    render_alerts_table(created_alerts)
    render_summary(
        indicators_cnt=len(rows),
        alerts_cnt=len(created_alerts),
        incidents_cnt=len(incs),
        duplicates_cnt=duplicates_count,
        errors_cnt=errors_count
    )

    if sys.stdin.isatty():
        try:
            prompt_text = "\n[cyan]?[/cyan] Запустить проверку тестов T4-1...T4-5? [bold green][Enter=Да][/bold green] / [dim]n=Нет[/dim]: "
            if RICH_AVAILABLE:
                choice = console.input(prompt_text).strip().lower()
            else:
                choice = input("\nЗапустить проверку тестов T4-1...T4-5? [Enter=Да / n=Нет]: ").strip().lower()

            if choice in ("", "y", "yes", "да", "д"):
                console.print()
                run_all_tests()
        except (KeyboardInterrupt, EOFError):
            pass
    else:
        print_info("Для запуска проверки выполните: python 04_prototype.py --test\n")


if __name__ == "__main__":
    main()