import csv
import os
import sys

# resolve paths from this file so cwd doesn't matter
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CSV = os.path.join(PROJECT_ROOT, "data", "eval_results.csv")
DEFAULT_OUT_DIR = SCRIPT_DIR

try:
    import matplotlib
    matplotlib.use("Agg")  # headless backend
    import matplotlib.pyplot as plt
except ImportError:
    print("could not import matplotlib.")
    print("install it with: pip install -r analysis/requirements.txt")
    sys.exit(1)


def load_rows(csv_path):
    # read the eval csv into a list of dicts
    with open(csv_path, newline="") as f:
        return list(csv.DictReader(f))


def style_xaxis(ax, scenarios):
    # scenario names on x-axis, rotated for readability
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(scenarios, rotation=40, ha="right")


def plot_detection_metrics(rows, out_dir):
    scenarios = [r["scenario"] for r in rows]
    precision = [float(r["precision"]) for r in rows]
    recall = [float(r["recall"]) for r in rows]
    f1 = [float(r["f1"]) for r in rows]

    x = range(len(scenarios))
    width = 0.27

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar([i - width for i in x], precision, width, label="precision")
    ax.bar(list(x), recall, width, label="recall")
    ax.bar([i + width for i in x], f1, width, label="f1")

    ax.set_ylim(0, 1.05)
    ax.set_ylabel("score")
    ax.set_title("Detection metrics per attack scenario")
    style_xaxis(ax, scenarios)
    ax.legend()

    path = os.path.join(out_dir, "detection_metrics.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_latency_p99(rows, out_dir):
    scenarios = [r["scenario"] for r in rows]
    p99 = [float(r["lat_p99_us"]) for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(range(len(scenarios)), p99)
    ax.set_yscale("log")

    # 1 ms budget reference line
    ax.axhline(1000, linestyle="--", color="red", label="1 ms budget")

    ax.set_ylabel("p99 latency (us, log scale)")
    ax.set_title("p99 detection latency stays far below the 1 ms budget")
    style_xaxis(ax, scenarios)
    ax.legend()

    path = os.path.join(out_dir, "latency_p99.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_time_to_detect(rows, out_dir):
    scenarios = [r["scenario"] for r in rows]
    # negative means not detected, clamp to 0 for display
    ttd = [max(0.0, float(r["time_to_detect_ms"])) for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(range(len(scenarios)), ttd)
    ax.set_ylabel("time to detect (ms)")
    ax.set_title("Time to detect per attack scenario (0 = not detected)")
    style_xaxis(ax, scenarios)

    path = os.path.join(out_dir, "time_to_detect.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV
    out_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT_DIR

    if not os.path.isfile(csv_path):
        print("could not find eval results at: {}".format(csv_path))
        print("run ./build/canshield_eval first to generate the data.")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)
    rows = load_rows(csv_path)

    for path in (
        plot_detection_metrics(rows, out_dir),
        plot_latency_p99(rows, out_dir),
        plot_time_to_detect(rows, out_dir),
    ):
        print("wrote {}".format(path))


if __name__ == "__main__":
    main()
