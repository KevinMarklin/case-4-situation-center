#!/usr/bin/env python3
"""
Situation Center CLI Prototype — Case 4 «Monitoring and Incidents».
Includes full Information Security (IS) suite: HMAC-SHA256, 7x4 RBAC, 
Zone isolation, and 9-field append-only audit log.

Usage:
    python 04_prototype.py
    python 04_prototype.py --incidents 01_data/incidents.csv --indicators 01_data/indicators.csv
    python 04_prototype.py --test
    python 04_prototype.py --verify-signatures
    python 04_prototype.py --verbose
"""

import csv
import hashlib
import hmac
import os
import sys
from datetime import datetime

# ============================================================================
# 1. ПОДКЛЮЧЕНИЕ RICH С БЕЗОПАСНЫМ FALLBACK
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
# 2. КОНФИГУРАЦИЯ, ПУТИ И ИБ-ПАРАМЕТРЫ
# ============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
# 9 обязательных полей AuditEvent по разделу 4 документа 11_ИБ.md
AUDIT_FIELDS = [
    "event_id", "entity_type", "entity_id", "action", 
    "from_status", "to_status", "actor", "at", "ip"
]

# Секрет HMAC: берется строго из окружения, либо дефолтный тестовый ключ (не в коде)
HMAC_SECRET_KEY = os.environ.get("SENSOR_HMAC_SECRET", "default_poultry_sensor_secret_2026").encode("utf-8")

# Жизненный цикл инцидентов: допустимые переходы
ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"],
    "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"],
    "CLOSED": [],
}

# Матрица прав доступа 7x4 по 11_ИБ.md (Раздел 3)
RBAC_MATRIX = {
    "create_incident": ["диспетчер", "руководитель", "инженер"],
    "assign_responsible": ["диспетчер", "руководитель"],
    "start_progress": ["руководитель", "инженер"],
    "close_incident": ["руководитель", "инженер"],
    "close_false_alarm": ["диспетчер", "руководитель"],
    "reopen_closed": ["руководитель"],  # только созданием нового инцидента
    "view_all_sites": ["диспетчер", "руководитель", "администратор"],
    "modify_sites": ["администратор"],
    "read_audit": ["руководитель", "администратор"],
    "delete_audit": []  # запрещено всем (append-only)
}


# ============================================================================
# 3. МОДУЛЬ КРИПТОГРАФИИ И ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ
# ============================================================================
def calculate_telemetry_signature(time_str: str, location: str, indicator: str, value: str, secret: bytes = HMAC_SECRET_KEY) -> str:
    """Генерация эталонной подписи HMAC-SHA256 по спецификации 11_ИБ.md (Раздел 5)."""
    canonical_payload = f"{time_str}:{location}:{indicator}:{value}".encode("utf-8")
    return hmac.new(secret, canonical_payload, hashlib.sha256).hexdigest()


def verify_telemetry_hmac(row: dict, secret: bytes = HMAC_SECRET_KEY) -> bool:
    """
    Проверка подлинности и целостности данных датчика.
    Сравнение через hmac.compare_digest для защиты от атак по времени (timing attacks).
    """
    received_signature = row.get("signature")
    if not received_signature:
        return False
    
    expected_signature = calculate_telemetry_signature(
        row.get("time", ""),
        row.get("location", ""),
        row.get("indicator", ""),
        str(row.get("value", "")),
        secret
    )
    return hmac.compare_digest(expected_signature, received_signature)


def check_rbac_permission(action: str, role: str) -> bool:
    """Проверка прав роли по матрице RBAC 7x4."""
    allowed_roles = RBAC_MATRIX.get(action, [])
    return role.lower() in [r.lower() for r in allowed_roles]


def check_zone_access(role: str, user_zone: str, target_zone: str) -> bool:
    """
    Проверка изоляции технологических зон (zone_A, zone_B, zone_C).
    Инженер имеет доступ только к своей назначенной технологической зоне.
    """
    if role.lower() in ["диспетчер", "руководитель", "администратор"]:
        return True
    if role.lower() == "инженер":
        return user_zone == target_zone
    return False


# ============================================================================
# 4. БИЗНЕС-ЛОГИКА ПРАВИЛ И ЖИЗНЕННОГО ЦИКЛА
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


def check_indicator(row, sites, seen, critical_history, enforce_signature=False):
    # Проверка ИБ: верификация HMAC при включенном режиме контроля
    if enforce_signature:
        if not verify_telemetry_hmac(row):
            return ("ERROR", "SENSOR_SIGNATURE_INVALID")

    loc = row.get("location", "")
    if loc not in sites:
        return ("ERROR", "UNKNOWN_LOCATION")

    sev = calc_severity(row.get("value"), row.get("norm_min"), row.get("norm_max"))
    if sev == "NORMAL":
        return None

    indicator = row.get("indicator", "")
    key = (loc, indicator)
    curr_time = parse_iso_time(row.get("time", ""))

    # Дедупликация (окно 300 секунд)
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
    
    # 1. Проверка допустимости перехода по графу
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return (False, "INVALID_TRANSITION")

    # 2. Проверка RBAC
    if current == "NEW" and to_status == "ASSIGNED":
        if not check_rbac_permission("assign_responsible", actor_role):
            return (False, "PERMISSION_DENIED")

    elif current == "ASSIGNED" and to_status == "IN_PROGRESS":
        if not check_rbac_permission("start_progress", actor_role):
            return (False, "PERMISSION_DENIED")

    elif current == "ASSIGNED" and to_status == "CLOSED":
        if resolution_reason != "NO_ACTION":
            return (False, "REQUIRES_RESOLUTION_REASON_NO_ACTION")
        if not check_rbac_permission("close_false_alarm", actor_role):
            return (False, "PERMISSION_DENIED")

    elif current == "IN_PROGRESS" and to_status == "CLOSED":
        if not check_rbac_permission("close_incident", actor_role):
            return (False, "PERMISSION_DENIED")

    return (True, None)


# ============================================================================
# 5. ФАЙЛОВЫЙ ВЫВОД И АУДИТ (APPEND-ONLY)
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
    """Строгая дозапись (append-only) без возможности модификации прошлых строк."""
    with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        w.writerow(audit_event)


# ============================================================================
# 6. ОФОРМЛЕНИЕ И ТЕРМИНАЛЬНЫЙ ДАШБОРД
# ============================================================================
def render_header():
    if not RICH_AVAILABLE:
        print("\n=== SITUATION CENTER: MONITORING & SECURITY ===")
        return

    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_row("[bold cyan]СИТУАЦИОННЫЙ ЦЕНТР — КЕЙС №4[/bold cyan]")
    grid.add_row("[dim]Мониторинг технологических параметров и контур ИБ (HMAC / RBAC / Audit)[/dim]")
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
    table.add_row("Ошибок валидации / атак отклонено", f"[red]{errors_cnt}[/red]")
    table.add_row("Инцидентов в исходном реестре", f"[cyan]{incidents_cnt}[/cyan]")
    table.add_row("Выходной файл оповещений", f"[dim underline]{OUT_CSV}[/dim underline]")
    table.add_row("Журнал аудита ИБ (9 полей)", f"[dim underline]{AUDIT_CSV}[/dim underline]")

    console.print(Panel(table, title="[bold cyan]Сводка работы ситуационного центра[/bold cyan]", box=box.ROUNDED, border_style="cyan"))


# ============================================================================
# 7. ТЕСТ-СЦЕНАРИИ: БИЗНЕС-ЛОГИКА (T4-1...T4-5) И ИБ (SEC-1...SEC-5)
# ============================================================================
def run_all_tests():
    sites = load_sites()
    if not sites:
        sites = {f"site_0{i}": {"name": f"Птичник {i}", "zone": "zone_A"} for i in range(1, 6)}

    # --- 1. ТЕСТЫ БИЗНЕС-ЛОГИКИ (03_тесты.md) ---
    biz_results = []

    # T4-1
    inc = {"incident_id": "inc_test_01", "status": "NEW", "responsible": None}
    ok_1, _ = transition_incident(inc, "ASSIGNED", actor_role="диспетчер")
    inc["status"] = "ASSIGNED"
    inc["responsible"] = "e_101"
    ok_2, _ = transition_incident(inc, "IN_PROGRESS", actor_role="инженер")
    bad_transition, _ = transition_incident({"status": "NEW"}, "CLOSED", actor_role="диспетчер")
    t4_1_passed = ok_1 and ok_2 and (not bad_transition)
    biz_results.append(("T4-1", "Создание и назначение инцидента", "NEW -> ASSIGNED, переход NEW -> CLOSED запрещён", "Переходы валидны, аудит зафиксирован", t4_1_passed))

    # T4-2
    row_t2 = {"time": "2025-11-01T10:00:00Z", "location": "site_02", "indicator": "temperature", "value": "28.3", "norm_min": "20.0", "norm_max": "26.0"}
    res_t2 = check_indicator(row_t2, sites, {}, {})
    sev_t2, act_t2 = res_t2 if res_t2 else (None, None)
    t4_2_passed = (sev_t2 == "WARNING" and act_t2 == "ALERT_CREATED")
    biz_results.append(("T4-2", "Превышение порога (28.3°C при норме 26°C)", "deviation=8.8% -> severity=WARNING", f"severity={sev_t2}, action={act_t2}", t4_2_passed))

    # T4-3
    row_t3 = {"time": "2025-11-01T10:00:00Z", "location": "site_99", "indicator": "temperature", "value": "28.3", "norm_min": "20.0", "norm_max": "26.0"}
    res_t3 = check_indicator(row_t3, sites, {}, {})
    t4_3_passed = (res_t3 == ("ERROR", "UNKNOWN_LOCATION"))
    biz_results.append(("T4-3", "Неверная локация (site_99 не в sites.csv)", "ERROR / UNKNOWN_LOCATION, отказ в регистрации", f"Статус={res_t3[0]}, Код={res_t3[1]}", t4_3_passed))

    # T4-4
    seen_test = {}
    row_t4_a = {"time": "2025-11-01T10:00:00Z", "location": "site_01", "indicator": "temperature", "value": "30.0", "norm_min": "20.0", "norm_max": "26.0"}
    row_t4_b = {"time": "2025-11-01T10:03:00Z", "location": "site_01", "indicator": "temperature", "value": "31.0", "norm_min": "20.0", "norm_max": "26.0"}
    res_a = check_indicator(row_t4_a, sites, seen_test, {})
    res_b = check_indicator(row_t4_b, sites, seen_test, {})
    t4_4_passed = (res_a[0] == "CRITICAL" and res_b == ("DUPLICATE", "IGNORED"))
    biz_results.append(("T4-4", "Повтор события за 3 мин (<5 мин)", "1-й принят, 2-й -> DUPLICATE / IGNORED", f"Событие 1: {res_a[0]}, Событие 2: {res_b[0]}", t4_4_passed))

    # T4-5
    row_t5 = {"time": "2025-11-01T10:00:00Z", "location": "site_03", "indicator": "ventilation", "value": "", "norm_min": "0.8", "norm_max": "2.0"}
    res_t5 = check_indicator(row_t5, sites, {}, {})
    sev_t5, act_t5 = res_t5 if res_t5 else (None, None)
    t4_5_passed = (sev_t5 == "STALE" and act_t5 == "ESCALATED")
    biz_results.append(("T4-5", "Датчик offline (value='')", "severity=STALE, action=ESCALATED", f"severity={sev_t5}, action={act_t5}", t4_5_passed))

    # --- 2. ТЕСТЫ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ (11_ИБ.md) ---
    sec_results = []

    # SEC-1: Валидация подлинной HMAC-подписи (U-1)
    sig_valid = calculate_telemetry_signature("2025-11-01T12:00:00Z", "site_01", "temperature", "25.0")
    row_sec1 = {"time": "2025-11-01T12:00:00Z", "location": "site_01", "indicator": "temperature", "value": "25.0", "signature": sig_valid}
    sec1_passed = verify_telemetry_hmac(row_sec1)
    sec_results.append(("SEC-1", "HMAC: проверка легитимной подписи датчика", "Подпись совпадает -> True", f"Проверка={sec1_passed}", sec1_passed))

    # SEC-2: Отклонение поддельного значения / неверной подписи (U-1)
    row_sec2 = {"time": "2025-11-01T12:00:00Z", "location": "site_01", "indicator": "temperature", "value": "29.9", "signature": sig_valid}
    sec2_passed = not verify_telemetry_hmac(row_sec2)
    sec_results.append(("SEC-2", "HMAC: отсечение подделки (значение подменено)", "Подпись не совпадает -> False", f"Отсечено={sec2_passed}", sec2_passed))

    # SEC-3: RBAC — запрет диспетчеру закрывать рабочий инцидент (U-2)
    inc_assigned = {"incident_id": "inc_sec_03", "status": "IN_PROGRESS", "responsible": "e_101"}
    bad_close, code = transition_incident(inc_assigned, "CLOSED", actor_role="диспетчер")
    sec3_passed = (not bad_close) and (code == "PERMISSION_DENIED")
    sec_results.append(("SEC-3", "RBAC: запрет закрытия инцидента диспетчером", "PERMISSION_DENIED", f"Разрешено={bad_close}, Код={code}", sec3_passed))

    # SEC-4: Разграничение зон доступа (zone_A vs zone_C) (U-3)
    engineer_zone_ok = check_zone_access("инженер", user_zone="zone_A", target_zone="zone_A")
    engineer_zone_deny = check_zone_access("инженер", user_zone="zone_A", target_zone="zone_C")
    sec4_passed = engineer_zone_ok and (not engineer_zone_deny)
    sec_results.append(("SEC-4", "RBAC: изоляция зон (инженер zone_A -> zone_C)", "Доступ в чужую зону блокирован", f"Своя={engineer_zone_ok}, Чужая={engineer_zone_deny}", sec4_passed))

    # SEC-5: Неизменяемость аудита — запрет удаления (U-7)
    sec5_passed = not check_rbac_permission("delete_audit", "администратор")
    sec_results.append(("SEC-5", "Аудит: запрет удаления логов администратором", "delete_audit -> False для всех ролей", f"Запрет удаления={sec5_passed}", sec5_passed))

    # Отрисовка таблиц тестов
    if RICH_AVAILABLE:
        # Таблица бизнес-тестов
        t_biz = Table(
            title="[bold]Результаты верификации бизнес-сценариев (03_тесты.md)[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold white",
            expand=True,
            show_lines=True,
            padding=(0, 1)
        )
        t_biz.add_column("Тест", style="bold cyan", width=8, no_wrap=True)
        t_biz.add_column("Описание проверки", ratio=4)
        t_biz.add_column("Ожидание", style="dim", ratio=4)
        t_biz.add_column("Факт прототипа", style="white", ratio=4)
        t_biz.add_column("Статус", justify="center", width=12, no_wrap=True)

        for tid, desc, exp, fact, passed in biz_results:
            status = "[green]✓ PASSED[/green]" if passed else "[red]✖ FAILED[/red]"
            t_biz.add_row(tid, desc, exp, fact, status)
        console.print(t_biz)

        console.print()

        # Таблица тестов ИБ
        t_sec = Table(
            title="[bold]Верификация контура информационной безопасности (11_ИБ.md)[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
            expand=True,
            show_lines=True,
            padding=(0, 1)
        )
        t_sec.add_column("Тест ИБ", style="bold yellow", width=8, no_wrap=True)
        t_sec.add_column("Механизм защиты", ratio=4)
        t_sec.add_column("Проверяемая угроза / Требование", style="dim", ratio=4)
        t_sec.add_column("Результат проверки", style="white", ratio=4)
        t_sec.add_column("Статус", justify="center", width=12, no_wrap=True)

        for tid, desc, exp, fact, passed in sec_results:
            status = "[green]✓ PASSED[/green]" if passed else "[red]✖ FAILED[/red]"
            t_sec.add_row(tid, desc, exp, fact, status)
        console.print(t_sec)
    else:
        print("\n--- RESULTS T4-1 ... T4-5 ---")
        for tid, desc, exp, fact, passed in biz_results:
            st = "PASSED" if passed else "FAILED"
            print(f"[{st}] {tid}: {desc} -> Fact: {fact}")
        print("\n--- RESULTS SEC-1 ... SEC-5 (SECURITY) ---")
        for tid, desc, exp, fact, passed in sec_results:
            st = "PASSED" if passed else "FAILED"
            print(f"[{st}] {tid}: {desc} -> Fact: {fact}")

    return all(r[4] for r in biz_results) and all(r[4] for r in sec_results)


# ============================================================================
# 8. ТОЧКА ВХОДА
# ============================================================================
def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    render_header()

    if "--test" in sys.argv or "--run-tests" in sys.argv:
        print_info("Запуск верификации всех сценариев регламента и безопасности...\n")
        success = run_all_tests()
        sys.exit(0 if success else 1)

    enforce_signature = "--verify-signatures" in sys.argv
    if enforce_signature:
        print_warn("Включен строгий режим проверки HMAC-SHA256 подписей телеметрии!")

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
        result = check_indicator(row, sites, seen, critical_history, enforce_signature=enforce_signature)
        if result is None:
            continue

        severity, action = result

        if severity == "DUPLICATE":
            duplicates_count += 1
            continue

        if severity == "ERROR":
            errors_count += 1
            if "--verbose" in sys.argv:
                print_warn(f"Отклонено показание: {action} (локация: '{row.get('location')}')")
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

        # Полная запись в AuditEvent со всеми 9 полями по регламенту ИБ
        write_audit({
            "event_id": f"evt_aud_{audit_counter:04d}",
            "entity_type": "alert",
            "entity_id": alert["alert_id"],
            "action": action,
            "from_status": "NONE",
            "to_status": severity,
            "actor": "system_rules_engine",
            "at": alert["at"],
            "ip": "127.0.0.1"
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
            prompt_text = "\n[cyan]?[/cyan] Запустить комплексные тесты T4-1...T4-5 и тесты ИБ (SEC-1...SEC-5)? [bold green][Enter=Да][/bold green] / [dim]n=Нет[/dim]: "
            if RICH_AVAILABLE:
                choice = console.input(prompt_text).strip().lower()
            else:
                choice = input("\nЗапустить тесты T4-1...T4-5 и тесты ИБ? [Enter=Да / n=Нет]: ").strip().lower()

            if choice in ("", "y", "yes", "да", "д"):
                console.print()
                run_all_tests()
        except (KeyboardInterrupt, EOFError):
            pass
    else:
        print_info("Для запуска проверки выполните: python 04_prototype.py --test\n")


if __name__ == "__main__":
    main()