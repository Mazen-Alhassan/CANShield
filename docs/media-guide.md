# adding photos / screenshots

Put images in `docs/images/` and link them from the README so the repo has something visual.

**Already in the repo** (rendered from real program output): `docs/images/demo.gif` (the live
monitor catching a spoof) and `docs/images/eval-run.png` (the evaluation campaign), both wired
into the README. Add your own below or replace these.

Here's what else is worth capturing and how.

## 1. software screenshots (easiest, do these first)

**IDS catching an attack** — the single best screenshot. Run:

```sh
./scripts/run_demo.sh
```

Screenshot the terminal from the `[ALERT] ...` lines through the `---- summary ----` block.
It shows multiple detectors firing on one attack plus the sub-microsecond latency line.

**Evaluation table** — run the full eval and screenshot the per-scenario table:

```sh
./build/canshield_eval | less     # or just screenshot the table it prints
```

**Result charts** — these are already generated as PNGs, no screenshot needed:
`analysis/detection_metrics.png`, `analysis/latency_p99.png`, `analysis/time_to_detect.png`.
Regenerate with `.venv/bin/python analysis/plot_results.py` after an eval run.

**Live traffic** (optional, nicer if you have vcan) — `candump vcan0` next to the monitor.

## 2. real-life photos (only if you build the hardware)

If you set up the Raspberry Pi bench from `deployment-raspberry-pi.md`, photograph:

- the two Pis + CAN HATs wired together (CANH/CANL + termination resistors) — a clear top-down shot
- a laptop terminal running `canshield_monitor --iface can0` next to the rig
- close-up of the CAN transceiver / HAT board

Good photo tips: bright even light, plain background, fill the frame with the rig, hold steady.

## 3. put them in the readme

Save files as e.g. `docs/images/ids-alerts.png` and reference them:

```markdown
![IDS catching an rpm spoof](docs/images/ids-alerts.png)
```

The results chart is already wired into the README; swap or add your own screenshots the same way.

## what NOT to shoot

Don't stage anything against a real vehicle's bus — this is a bench testbed and the traffic is
synthetic. Keep photos to the dev rig / virtual setup.
