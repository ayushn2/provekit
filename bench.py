import subprocess
import re
import statistics
from pathlib import Path
import csv
import psutil

RUNS = 20
FEATURES = ["sha2","sha3","blake3","skyscraper"]

BIN = ["./target/release/provekit-cli"]

def cmd_with_feature(feature, args):
    return [
        "cargo", "run", "--release",
        "-p", "provekit-cli",
        "--no-default-features",
        "--features", f"provekit-common/{feature}",
        "--bin", "provekit-cli",
        "--",
        *args
    ]

PREPARE_ARGS = [
    "prepare",
    "noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json",
    "--pkp", "prover.pkp",
    "--pkv", "verifier.pkv",
]
PROVE_ARGS   = ["prove", "prover.pkp", "noir-examples/noir-passport-examples/complete_age_check/Prover.toml", "-o", "proof.np"]
VERIFY_ARGS  = ["verify", "verifier.pkv", "proof.np"]

# ================= REGEX =================
RE_TIME = re.compile(r"run:\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\s*duration", re.IGNORECASE)
RE_SIZE = re.compile(r"size=(\d+)")

# ================= HELPERS =================

def cargo_clean():
    print("Running cargo clean...", flush=True)
    subprocess.run(["cargo", "clean"], check=True)

def run_and_measure(cmd):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    p = psutil.Process(proc.pid)

    peak_cpu = 0.0
    peak_mem = 0.0  # in MB

    # Prime cpu_percent measurement
    try:
        p.cpu_percent(interval=None)
    except psutil.NoSuchProcess:
        pass

    while proc.poll() is None:
        try:
            cpu = p.cpu_percent(interval=0.1)
            mem = p.memory_info().rss / (1024 * 1024)  # MB

            peak_cpu = max(peak_cpu, cpu)
            peak_mem = max(peak_mem, mem)

        except psutil.NoSuchProcess:
            break

    stdout, _ = proc.communicate()
    return stdout, peak_cpu, peak_mem

def extract_prove_verify_times(log: str):
    # Normalize unicode spaces and strip ANSI escape codes
    cleaned = log.replace("\u202f", " ").replace("\xa0", " ")
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", cleaned)  # remove ANSI colors if any

    # Very permissive: find the LAST occurrence of `run: <number> <unit> duration`
    pattern = re.compile(r"run:\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\s*duration", re.IGNORECASE)
    matches = pattern.findall(cleaned)

    if not matches:
        print("\n--- FAILED OUTPUT START ---")
        print(cleaned)
        print("--- FAILED OUTPUT END ---\n")
        raise RuntimeError("No run timings found in output")

    val, unit = matches[-1]
    v = float(val)
    if unit.lower() == "s":
        v *= 1000.0
    return v

def extract(regex, text, cast=float, label=""):
    matches = list(regex.finditer(text))
    if not matches:
        print("\n--- FAILED OUTPUT START ---")
        print(text)
        print("--- FAILED OUTPUT END ---\n")
        raise RuntimeError(f"Failed to extract {label or regex.pattern}")

    last = matches[-1].groups()

    # If regex has 2 capture groups (time + unit)
    if len(last) == 2:
        val, unit = last
        v = float(val)
        if unit == "s":
            v *= 1000.0
        return v

    # If regex has 1 capture group (e.g. size)
    if len(last) == 1:
        return cast(last[0])

    raise RuntimeError("Unexpected regex match format")


def clean():
    for f in ["prover.pkp", "verifier.pkv", "proof.np"]:
        Path(f).unlink(missing_ok=True)


def file_size(path):
    return Path(path).stat().st_size if Path(path).exists() else 0


# ================= BENCH =================

results = []

for feature in FEATURES:
    print(f"\n===== BENCHMARKING {feature.upper()} =====", flush=True)

    # print(f"Building for {feature}...", flush=True)
    # subprocess.run([
    #     "cargo", "build",
    #     "--release",
    #     "--no-default-features",
    #     "--features", feature,
    #     "--bin", "provekit-cli"
    # ], check=True, stdout=sys.stdout, stderr=sys.stderr)

    prepare_times = []
    prove_times = []
    verify_times = []

    prove_mem_peaks = []
    verify_mem_peaks = []

    proof_sizes = []
    pkp_sizes = []
    pkv_sizes = []

    for i in range(RUNS):
        print(f"Run {i+1}/{RUNS}")
        clean()

        # -------- PREPARE --------
        out_prepare, prepare_cpu, prepare_mem = run_and_measure(
            cmd_with_feature(feature, [
                "prepare",
                "noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json",
                "--pkp", "prover.pkp",
                "--pkv", "verifier.pkv"
            ],)
        )
        # prepare_times.append(extract(RE_TIME, out_prepare, float, "prepare time"))

        pkp_sizes.append(file_size("prover.pkp"))
        pkv_sizes.append(file_size("verifier.pkv"))

        # -------- PROVE --------
        out_prove, prove_cpu, prove_mem = run_and_measure(
            cmd_with_feature(feature, [
                "prove",
                "prover.pkp",
                "noir-examples/noir-passport-examples/complete_age_check/Prover.toml",
                "-o", "proof.np"
            ])
        )
        prove_times.append(extract_prove_verify_times(out_prove))
        prove_mem_peaks.append(prove_mem)
        proof_sizes.append(extract(RE_SIZE, out_prove, int, "proof size"))

        # -------- VERIFY --------
        out_verify, verify_cpu, verify_mem = run_and_measure(
            cmd_with_feature(feature, [
                "verify",
                "verifier.pkv",
                "proof.np"
            ])
        )
        verify_times.append(extract_prove_verify_times(out_verify))
        verify_mem_peaks.append(verify_mem)
        
    

    results.append({
        "hash": feature,

        # Core metrics
        # "prepare_time_mean_ms": statistics.mean(prepare_times),
        # "prepare_time_var": statistics.pvariance(prepare_times),

        "prover_time_mean_ms": statistics.mean(prove_times),
        "prover_time_var": statistics.pvariance(prove_times),

        "verifier_time_mean_ms": statistics.mean(verify_times),
        "verifier_time_var": statistics.pvariance(verify_times),

        "prover_peak_rss_mean_mb": statistics.mean(prove_mem_peaks),
        "verifier_peak_rss_mean_mb": statistics.mean(verify_mem_peaks),

        # Sizes
        "proof_size_mean_bytes": statistics.mean(proof_sizes),
        "proof_size_var": statistics.pvariance(proof_sizes),

        "pkp_size_mean_bytes": statistics.mean(pkp_sizes),
        "pkv_size_mean_bytes": statistics.mean(pkv_sizes),
    })


# ================= WRITE CSV =================

out_file = "hash_benchmarks.csv"
with open(out_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print(f"\nSaved results to {out_file}")