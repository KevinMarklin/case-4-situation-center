#!/usr/bin/env python3
"""
CLI-прототип ситуационного центра — кейс 4.

Использование:
    python 04_прототип.py
    python 04_прототип.py --incidents incidents.csv --indicators indicators.csv

Что делает:
    читает indicators.csv, проверяет пороги, выводит alerts_out.csv,
    обрабатывает инциденты и переходы статусов.

TODO для команды:
    1. Дописать calc_severity() — 5 веток формулы из 02_правила.md.
    2. Дописать check_indicator() — правила A-1…A-5.
    3. Дописать deduplicate() — окно 5 минут.
    4. Дописать transition_incident() — допустимые и запрещённые переходы.
    5. Проверить на T4-1…T4-5.
"""
import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_CSV = os.path.join(BASE_DIR, "01_данные", "sites.csv")
INCIDENTS_CSV = os.path.join(BASE_DIR, "01_данные", "incidents.csv")
INDICATORS_CSV = os.path.join(BASE_DIR, "01_данные", "indicators.csv")
OUT_CSV = os.path.join(BASE_DIR, "alerts_out.csv")

OUT_FIELDS = ["alert_id", "at", "location", "indicator", "value", "severity", "action"]

ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"],
    "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"],
    "CLOSED": [],
}


def load_sites():
    """Прочитать sites.csv, вернуть set(site_id)."""
    active = set()
    try:
        with open(SITES_CSV, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                active.add(row["site_id"])
    except FileNotFoundError:
        print(f"WARN: {SITES_CSV} не найден", file=sys.stderr)
    return active


def calc_severity(value, norm_min, norm_max):
    """
    TODO: реализовать формулу из 02_правила.md:
      - value = "" → STALE
      - norm_min <= value <= norm_max → NORMAL
      - deviation_pct ≤ 10% → WARNING
      - deviation_pct > 10% → CRITICAL
    """
    if value == "" or value is None:
        return "STALE"
    v = float(value)
    lo, hi = float(norm_min), float(norm_max)
    if lo <= v <= hi:
        return "NORMAL"
    # ОБРАЗЕЦ — расчёт отклонения
    if v > hi:
        dev_pct = (v - hi) / hi * 100
    else:
        dev_pct = (lo - v) / lo * 100
    if dev_pct > 10:
        return "CRITICAL"
    return "WARNING"


def check_indicator(row, sites, seen, alerts_count):
    """
    TODO: реализовать A-1…A-5.
    Вернуть (severity, action) или None, или ("ERROR", code).
    """
    loc = row["location"]
    if loc not in sites:
        return ("ERROR", "UNKNOWN_LOCATION")

    sev = calc_severity(row["value"], row["norm_min"], row["norm_max"])
    if sev == "NORMAL":
        return None

    # TODO: дедупликация (A-5)
    # key = (loc, row["indicator"])
    # if key in seen and (now - seen[key]).seconds < 300:
    #     return ("DUPLICATE", "IGNORED")

    # TODO: автоинцидент при 2 CRITICAL подряд (A-3)
    # TODO: эскалация STALE (A-4)

    action = "ESCALATED" if sev in ("CRITICAL", "STALE") else "ALERT_CREATED"
    return (sev, action)


def write_alert(alert):
    new_file = not os.path.exists(OUT_CSV)
    with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        if new_file:
            w.writeheader()
        w.writerow(alert)


def transition_incident(incident, to_status, actor_role):
    """
    TODO: проверить допустимость перехода через ALLOWED_TRANSITIONS.
    Вернуть (True, None) или (False, "INVALID_TRANSITION").
    """
    current = incident["status"]
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return (False, "INVALID_TRANSITION")
    # TODO: проверить, что роль actor_role имеет право на этот переход
    return (True, None)


def main():
    incidents_path = INCIDENTS_CSV
    indicators_path = INDICATORS_CSV
    if "--incidents" in sys.argv:
        incidents_path = sys.argv[sys.argv.index("--incidents") + 1]
    if "--indicators" in sys.argv:
        indicators_path = sys.argv[sys.argv.index("--indicators") + 1]

    sites = load_sites()
    if not sites:
        print("❌ sites.csv пуст или не найден")
        sys.exit(2)

    alerts = 0
    seen = {}

    with open(indicators_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        result = check_indicator(row, sites, seen, alerts)
        if result is None:
            continue
        severity, action = result
        if severity == "ERROR":
            print(f"❌ {row['location']}: {action}")
            continue
        alert = {
            "alert_id": f"alrt_{alerts + 1:04d}",
            "at": row["time"],
            "location": row["location"],
            "indicator": row["indicator"],
            "value": row["value"],
            "severity": severity,
            "action": action,
        }
        write_alert(alert)
        alerts += 1

    # Опционально: проверить переходы на incidents.csv
    with open(incidents_path, encoding="utf-8") as f:
        incs = list(csv.DictReader(f))

    print(f"OK: indicators обработано: {len(rows)}")
    print(f"    алертов создано:       {alerts}")
    print(f"    incidents загружено:   {len(incs)}")
    print(f"    файл: {OUT_CSV}")


if __name__ == "__main__":
    main()