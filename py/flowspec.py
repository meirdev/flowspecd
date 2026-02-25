#!/usr/bin/env python3

import os
import sys
import time

PIPE_PATH = "/var/run/exabgp.cmd"


def main():
    sys.stderr.write(f"[flowspec-api] Listening on {PIPE_PATH}\n")
    sys.stderr.flush()

    while True:
        try:
            with open(PIPE_PATH, "r") as pipe:
                for line in pipe:
                    line = line.strip()
                    if line:
                        sys.stderr.write(f"[flowspec-api] Sending: {line}\n")
                        sys.stderr.flush()
                        sys.stdout.write(line + "\n")
                        sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[flowspec-api] Error: {e}\n")
            sys.stderr.flush()

            time.sleep(1)


if __name__ == "__main__":
    main()