#!/usr/bin/env python3

#By https://github.com/srdnlen/exploitfarm

import requests
from exploitfarm.models.enums import AttackMode
from dateutil.parser import parse as date_parser
from rich import print
from os.path import join as pjoin
from os.path import dirname
from typer import confirm
from exploitfarm import get_config

API_URL = "https://9.enowars.com"

with open(pjoin(dirname(__file__), "submitters", "enowars_submitter.py")) as f:
    SUBMITTER = f.read()

config = get_config()

if config.status["status"] != "setup":
    print("Server is not in setup mode")
    exit(1)

token = input("Enter your token: ").strip()

while True:
    try:
        my_team_id = int(input("Enter your team id: ").strip())
        break
    except Exception:
        pass
    print("Invalid team id")

auth = confirm("Do you want to set authentication?", default=True)
password = None
if auth:
    while True:
        password = input("Enter the password: ").strip()
        if len(password) > 0:
            check_password = input("Re-enter the password: ").strip()
            if password == check_password:
                break
            print("Passwords do not match")
            continue
        print("Password cannot be empty")

submitter_id = config.reqs.new_submitter(
    {"name": "Enowars submitter", "code": SUBMITTER})["id"]

# Da quello che ho visto ci sono due endpoint: /api/data/ips e /api/data/teams, che tecnicamente dovrebbero darci
# tutto quello che ci serve seguendo lo stesso ordine
# https://github.com/enowars/EnoCTFPortal/blob/df5f88b974c10050e8021c516c187da02dc9a1d1/EnoLandingPageBackend/Controllers/DataController.cs#L50
try:
    with (
        requests.get(API_URL + "/api/data/ips", timeout=5) as ips_resp,
        requests.get(API_URL + "/api/data/teams", timeout=5) as teams_resp,
    ):
        if ips_resp.status_code != 200 or teams_resp.status_code != 200:
            raise Exception(f"Could not fetch general info from {API_URL}")

        teams = teams_resp.json()
        ips = ips_resp.text.splitlines()
        confirmed_teams = []
        for id, team in enumerate(teams["confirmedTeams"]):
            if id == my_team_id:
                continue
            confirmed_teams.append(
                {
                    "name": team["name"],
                    "short_name": team["name"],
                    "host": ips[int(id)],
                }
            )
        config.reqs.new_teams(confirmed_teams)
except Exception as e:
    print(f"Error fetching teams: {e}")

# Forse i servizi si possono prendere da qui???
# https://github.com/enowars/EnoCTFPortal/blob/df5f88b974c10050e8021c516c187da02dc9a1d1/firstblood-discord-bot/main.py#L12
try:
    with requests.get(
        API_URL + "/scoreboard/scoreboard.json", timeout=5
    ) as services_resp:
        for service in services_resp.json()["services"]:
            config.reqs.new_service({"name": service["serviceName"]})
except Exception as e:
    print(f"Error fetching services: {e}")


print(
    config.reqs.configure_server(
        attack_mode=AttackMode.TICK_DELAY,
        submitter=submitter_id,
        attack_time_tick_delay=2,
        authentication_required=auth,
        password_hash=password,
        # presi dalle docs della gara
        start_time=date_parser("7/19/2025 12:00:00 PM UTC"),
        end_time=date_parser("7/19/2025 09:00:00 PM UTC"),
        tick_duration=60,
        flag_regex=r"ENO[A-Za-z0-9+\/=]{48}",
        # questo è guessato actually, nelle docs non c'è scritto
        flag_submit_limit=2500,
        submit_delay=0.1,
        submitter_timeout=30,
        set_running=True,
    )
)
