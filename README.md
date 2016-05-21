For now only **Python 3** is supported.

Tenhou.net doesn't store more than 40 your last games.
To prevent it, this script will store locally all your games logs
from tenhou.net server.

In future this script will send logs to my statistics server.

Script optionally support logs content downloading, to use it add -d flag
to arguments.

Example of usages:

1. Build meta file and download logs content: `python collect.py -m ~/data.txt -d ~/tenhou_logs/`
1. Build only meta file: `python collect.py -m ~/tenhou-meta.txt`