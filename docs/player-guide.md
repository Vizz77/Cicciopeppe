# ExploitFarm Player Guide

This guide is the minimal flow for running ExploitFarm during a competition.

The server coordinates attacks, stores exploit sources, receives flags, and submits
flags to the game platform. The server does not attack teams by itself.

The client is `xfarm`. It connects to the server, runs exploit code on the player
machine, extracts flags from stdout, and sends the results back to the server.

## 1. Start The Server

Run this on the server machine:

```bash
python3 run.py start --prebuilt --port 5050 --logs
```

Open the web interface:

```text
http://<SERVER_IP>:5050
```

The server admin must configure the platform from the web UI before players run
attacks:

- flag regex
- tick duration and attack mode
- teams and target hosts
- services
- submitter
- optional password

Stop the server:

```bash
python3 run.py stop
```

Stop the server and delete all saved data:

```bash
python3 run.py stop --clear
```

Use `--clear` only when you want to reset the instance.

## 2. Install And Configure The Client

Install the client on each player or worker machine.

From a released package:

```bash
python3 -m pip install -U xfarm
```

From this repository:

```bash
python3 -m pip install -U ./client
```

Configure the client:

```bash
xfarm -I config edit --address <SERVER_IP> --port 5050 --nickname <PLAYER_NAME>
```

If the server uses HTTPS:

```bash
xfarm -I config edit --address <SERVER_HOST> --port 443 --https --nickname <PLAYER_NAME>
```

Login if the server requires a password:

```bash
xfarm -I config login --password '<SERVER_PASSWORD>'
```

Check that the client can reach the server:

```bash
xfarm status
```

## 3. Add An Exploit

The easiest flow is interactive:

```bash
xfarm exploit init
```

Choose:

- exploit name
- language
- service

This creates an exploit folder with:

```text
config.toml
main.py, main.js, or another main file depending on the language
```

Enter the exploit folder:

```bash
cd <EXPLOIT_FOLDER>
```

For Python, a minimal exploit looks like this:

```python
from exploitfarm import *
import requests

host = get_host()

r = requests.get(f"http://{host}:8080/", timeout=5)
print(r.text)
```

The exploit must print flags to stdout. `xfarm` reads stdout, extracts flags using
the server regex, and sends the attack result to the server.

The generated `config.toml` controls how the exploit is executed:

```toml
interpreter = "python3"
run = "main.py"
```

When `xfarm` runs the exploit, it executes:

```bash
python3 main.py
```

For a custom script, edit `config.toml`:

```toml
interpreter = "bash"
run = "exploit.sh"
```

## 4. Test An Exploit On One Host

Run this from inside the exploit folder:

```bash
xfarm start --test <TARGET_HOST>
```

Example:

```bash
xfarm start --test 10.60.1.1
```

During execution, `xfarm` sets environment variables for the exploit:

```text
XFARM_HOST        target host
XFARM_TEAM        full team JSON
XFARM_EXPLOIT_ID  exploit id
XFARM_REMOTE_URL  server URL
XFARM_LOGIN_TOKEN auth token, if needed
```

Use `XFARM_HOST` as the target address in non-Python exploits.

## 5. Upload Or Update An Exploit

Run this from inside the exploit folder:

```bash
xfarm exploit push -m "working version"
```

This uploads the current source code to the server as a new exploit source version.

To download an exploit source from the server:

```bash
xfarm exploit download <EXPLOIT_ID>
```

To update a local exploit folder to the latest uploaded source:

```bash
xfarm exploit update
```

## 6. Server-Side Exploit Management

Players add exploits from the client. The server receives the exploit metadata and
source code; nobody should manually copy exploit files onto the server.

Server-side behavior:

- add exploit: created when a player runs `xfarm exploit init`
- add source version: uploaded when a player runs `xfarm exploit push` or `xfarm submit`
- run exploit: scheduled by the server, executed by connected clients
- stop worker scheduling: disable the exploit from the worker pool
- delete exploit: admin-only action from the web UI if permanent removal is needed

The fastest way for a player to stop an exploit from being scheduled by workers is:

```bash
xfarm submit --off
```

Run that from inside the exploit folder.

## 7. Run An Exploit From One Client

Run this from inside the exploit folder:

```bash
xfarm start
```

This client runs this one exploit against all configured teams.

Use a fixed local process pool size:

```bash
xfarm start --pool-size 40
```

Use non-interactive log output:

```bash
xfarm -I start --pool-size 40
```

Stop it with `Ctrl+C`.

## 8. Run Exploits With The Worker Pool

Worker pool mode is the recommended distributed mode.

Start a worker client on each machine:

```bash
xfarm -I worker 40
```

`40` is the number of exploit processes this worker can run in parallel.

Start a background worker:

```bash
xfarm -I worker 40 --demonized --log-file ~/.exploitfarm/worker.log
```

Enable the current exploit on the worker pool:

```bash
xfarm submit -m "enable on workers"
```

This does two things:

- uploads the exploit source to the server
- enables `run_on_workers` for that exploit

The server then assigns that exploit to connected worker clients. Worker clients
download the exploit source, run it against assigned teams, and send results back.

Remove the current exploit from the worker pool:

```bash
xfarm submit --off
```

This stops the worker pool from scheduling that exploit.

## 9. Kill A Worker Client

Stop a foreground worker:

```text
Ctrl+C
```

Kill a background worker:

```bash
xfarm -I worker --kill
```

Read the background worker logs:

```bash
tail -f ~/.exploitfarm/worker.log
```

## 10. Attack Groups

Normal attack groups are useful when a set of clients should collaborate on one
specific exploit.

Create a group from inside an exploit folder:

```bash
xfarm group create --name "service-a exploit"
```

Join a group:

```bash
xfarm group join --group <GROUP_ID> --queue 40
```

Join and start the group:

```bash
xfarm group join --group <GROUP_ID> --queue 40 --trigger-start
```

Important: in the current version, a normal attack group is linked to one exploit.
Use the worker pool if you want the server to schedule multiple enabled exploits
across available worker clients.

## 11. Common Commands

```bash
# client status
xfarm status

# list exploits
xfarm status exploits

# list teams
xfarm status teams

# create exploit
xfarm exploit init

# test exploit on one host
xfarm start --test <TARGET_HOST>

# upload source
xfarm exploit push -m "message"

# run locally against all teams
xfarm start

# start worker
xfarm -I worker 40

# enable exploit on workers
xfarm submit -m "enable on workers"

# remove exploit from workers
xfarm submit --off

# kill background worker
xfarm -I worker --kill
```
