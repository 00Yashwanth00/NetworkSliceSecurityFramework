import os
import time
import threading
import requests
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from cicflowmeter.sniffer import create_sniffer

API_BASE_URL = "http://localhost:5001/api/tests"
DOWNLOAD_DIR = "pcaps"
OUTPUT_CSV = "new_flow_dataset_2.csv"

DOWNLOAD_WORKERS = 4      # I/O-bound: safe to parallelize with threads
EXTRACTION_WORKERS = 2    # CPU-bound: use processes, keep low (scapy is heavy per-process)

# Global set to remember runs that we've given up on entirely (after repeated
# 404s) so we stop retrying them forever.
FAILED_RUNS = set()
FAILED_RUNS_LOCK = threading.Lock()

# A 404 right when a run completes is often just a race: MMT Studio marks the
# run "completed" in the API slightly before the PCAP file finishes being
# written/served. So we don't blacklist on the first 404 - we retry a few
# times with backoff, and only give up permanently after that.
RETRY_STATE = {}          # run_id -> number of 404 attempts so far
RETRY_STATE_LOCK = threading.Lock()
MAX_404_RETRIES = 6       # ~6 cycles * 5s = give a run up to ~30s to appear


def mark_failed(run_id):
    with FAILED_RUNS_LOCK:
        FAILED_RUNS.add(run_id)
    with RETRY_STATE_LOCK:
        RETRY_STATE.pop(run_id, None)


def register_not_ready(run_id):
    """
    Record a 404 for this run without permanently giving up on it yet.
    Returns True if the run should be retried again later, False if it's
    exhausted its retries and should now be treated as permanently failed.
    """
    with RETRY_STATE_LOCK:
        attempts = RETRY_STATE.get(run_id, 0) + 1
        RETRY_STATE[run_id] = attempts
        return attempts < MAX_404_RETRIES


def is_failed(run_id):
    with FAILED_RUNS_LOCK:
        return run_id in FAILED_RUNS


def fetch_completed_runs():
    """Fetch all completed test runs from the MMT Studio API."""
    try:
        response = requests.get(API_BASE_URL, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get("results", [])
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching runs from MMT API: {e}")
        return []


def download_pcap(run_id, save_path):
    """Download the PCAP file for a specific run. I/O-bound -> safe under threads."""
    if is_failed(run_id):
        return False

    try:
        url = f"{API_BASE_URL}/runs/{run_id}/pcap"
        response = requests.get(url, stream=True, timeout=10)

        if response.status_code == 200:
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            if os.path.exists(save_path) and os.path.getsize(save_path) > 0:
                print(f"[+] Downloaded PCAP: {save_path} ({os.path.getsize(save_path)} bytes)")
                # Successful download - clear any retry history for this run.
                with RETRY_STATE_LOCK:
                    RETRY_STATE.pop(run_id, None)
                return True
            else:
                print(f"[!] Empty PCAP received for run {run_id}, skipping.")
                mark_failed(run_id)
                return False
        elif response.status_code == 404:
            if register_not_ready(run_id):
                print(f"[~] PCAP not ready yet for run {run_id} (404) - will retry.")
            else:
                print(f"[!] PCAP still 404 for run {run_id} after {MAX_404_RETRIES} attempts, giving up.")
                mark_failed(run_id)
            return False
        else:
            print(f"[!] Unexpected status {response.status_code} for run {run_id}, marking as skipped.")
            mark_failed(run_id)
            return False
    except requests.exceptions.RequestException as e:
        print(f"[!] Error downloading PCAP for run {run_id}: {e}")
        mark_failed(run_id)
        return False


def _sniffer_is_alive(sniffer):
    """
    scapy's AsyncSniffer has no is_alive() method of its own - the running
    thread lives at sniffer.thread. Fall back to the .running flag if the
    thread attribute isn't there (varies a bit across scapy versions).
    """
    thread = getattr(sniffer, "thread", None)
    if thread is not None:
        return thread.is_alive()
    return bool(getattr(sniffer, "running", False))


def stop_sniffer(sniffer, session, join_timeout=15.0):
    """
    Actually stop a CICFlowMeter sniffer, instead of just giving up on it.

    sniffer.join(timeout=...) only stops *waiting* for the thread - it does NOT
    stop the thread itself. If parsing takes longer than the timeout, the old
    code silently returned while the sniffer kept running in the background.
    Across a 5s polling loop that runs forever, this leaks live sniffer threads
    every cycle, which is the most likely cause of the "hang" you were seeing.
    """
    sniffer.join(timeout=join_timeout)

    if _sniffer_is_alive(sniffer):
        print(f"[!] Sniffer did not finish within {join_timeout}s, stopping it explicitly.")
        try:
            sniffer.stop()
        except Exception as e:
            print(f"[!] Error calling sniffer.stop(): {e}")
        # Give it a short grace period to actually exit after stop()
        sniffer.join(timeout=5.0)
        if _sniffer_is_alive(sniffer):
            print("[!] Sniffer thread still alive after stop() - abandoning it "
                  "(this pcap's extraction will be treated as failed).")
            return False

    if hasattr(session, "_gc_stop"):
        session._gc_stop.set()
        session._gc_thread.join(timeout=2.0)

    try:
        session.flush_flows()
    except Exception as e:
        print(f"[!] Error flushing flows: {e}")
        return False

    return True


def extract_flow_features(pcap_path, output_csv_path):
    """
    Extract flow features from PCAP using CICFlowMeter.

    CPU-bound (packet parsing in pure Python via scapy) - do NOT run this
    under ThreadPoolExecutor. Threads fight over the GIL and, worse, scapy
    keeps some global/module-level state, so concurrent sniffer instances
    in the same process can step on each other and appear to freeze.
    Run this via ProcessPoolExecutor instead, which gives each extraction
    its own interpreter and its own scapy state.
    """
    print(f"[*] Extracting flow features: {pcap_path} -> {output_csv_path}")
    try:
        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            print(f"[!] Skipping invalid PCAP file: {pcap_path}")
            return False

        sniffer, session = create_sniffer(
            input_file=pcap_path,
            input_interface=None,
            output_mode="csv",
            output=output_csv_path,
            verbose=False,
        )
        sniffer.start()

        if not stop_sniffer(sniffer, session, join_timeout=15.0):
            return False

        if os.path.exists(output_csv_path) and os.path.getsize(output_csv_path) > 0:
            print(f"[OK] Successfully saved flow features: {output_csv_path}")
            return True
        else:
            print(f"[!] No flows generated for {pcap_path}")
            return False
    except Exception as e:
        print(f"[!] Error extracting flow features from {pcap_path}: {e}")
        return False


def get_run_id(run):
    return run if isinstance(run, str) else run.get("run_id", str(run))


def find_pending_pcaps():
    """Any .pcap in DOWNLOAD_DIR that doesn't yet have a corresponding _flows.csv."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    pending = []
    for f in os.listdir(DOWNLOAD_DIR):
        if not f.endswith(".pcap"):
            continue
        run_id = f[:-len(".pcap")]
        if is_failed(run_id):
            continue
        csv_path = os.path.join(DOWNLOAD_DIR, f"{run_id}_flows.csv")
        if not os.path.exists(csv_path):
            pending.append(run_id)
    return pending


def backfill_existing_pcaps():
    """
    One-shot catch-up: extract any already-downloaded pcaps that never made
    it into flow_dataset.csv (e.g. the daemon was stopped/restarted before
    it got to them), then append the results to the master dataset.
    Safe to run any time - already-extracted runs are skipped automatically.
    """
    bootstrap_master_dataset()

    pending = find_pending_pcaps()
    if not pending:
        print("[*] No pending pcaps found - nothing to backfill.")
        return

    print(f"[*] Found {len(pending)} pcap(s) missing from the master dataset. Extracting...")

    new_csv_paths = []
    with ProcessPoolExecutor(max_workers=EXTRACTION_WORKERS) as executor:
        futures = [executor.submit(extraction_step, run_id) for run_id in pending]
        for future in as_completed(futures):
            try:
                csv_path = future.result()
                if csv_path:
                    new_csv_paths.append(csv_path)
            except Exception as e:
                print(f"[!] Extraction worker error: {e}")

    append_new_flows_to_master(new_csv_paths)
    print(f"[*] Backfill complete: {len(new_csv_paths)}/{len(pending)} pcap(s) added.")


def download_step(run):
    """Stage 1 (threaded): ensure the PCAP for this run is on disk. Returns run_id or None."""
    run_id = get_run_id(run)
    if not run_id or is_failed(run_id):
        return None

    pcap_path = os.path.join(DOWNLOAD_DIR, f"{run_id}.pcap")
    csv_path = os.path.join(DOWNLOAD_DIR, f"{run_id}_flows.csv")

    # Already extracted in a previous cycle -> nothing to download.
    if os.path.exists(csv_path):
        return None

    if not os.path.exists(pcap_path):
        if not download_pcap(run_id, pcap_path):
            return None

    return run_id


def extraction_step(run_id):
    """Stage 2 (process pool): extract features, then clean up the raw PCAP. Runs in a worker process."""
    pcap_path = os.path.join(DOWNLOAD_DIR, f"{run_id}.pcap")
    csv_path = os.path.join(DOWNLOAD_DIR, f"{run_id}_flows.csv")

    if not os.path.exists(csv_path):
        if not extract_flow_features(pcap_path, csv_path):
            return None

    if os.path.exists(csv_path) and os.path.exists(pcap_path):
        try:
            os.remove(pcap_path)
            print(f"[cleanup] Auto-removed raw PCAP to save disk space: {pcap_path}")
        except Exception:
            pass

    return csv_path if os.path.exists(csv_path) else None


# Run IDs are used only internally for deduplication; they are NOT written to the dataset.
COMBINED_RUN_IDS = set()
MASTER_ROW_COUNT = 0


def _load_csv(csv_path):
    """Read one extracted flow CSV without adding any label."""
    df = pd.read_csv(csv_path)
    if df.empty:
        return None
    return df


def bootstrap_master_dataset():
    """
    One-time startup scan.

    The master dataset contains only the flow attributes generated by
    CICFlowMeter. No Label column is added.
    """
    global MASTER_ROW_COUNT
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    if os.path.exists(OUTPUT_CSV) and os.path.getsize(OUTPUT_CSV) > 0:
        try:
            existing = pd.read_csv(OUTPUT_CSV)
            MASTER_ROW_COUNT = len(existing)
            print(f"[*] Found existing {OUTPUT_CSV} with {MASTER_ROW_COUNT} rows.")
        except Exception as e:
            print(f"[!] Could not read existing {OUTPUT_CSV}: {e}")
        return

    all_csvs = [
        os.path.join(DOWNLOAD_DIR, f)
        for f in os.listdir(DOWNLOAD_DIR)
        if f.endswith("_flows.csv")
        and os.path.getsize(os.path.join(DOWNLOAD_DIR, f)) > 0
    ]

    if not all_csvs:
        return

    append_new_flows_to_master(all_csvs)


def append_new_flows_to_master(new_csv_paths):
    """
    Append newly extracted CICFlowMeter attributes to the master dataset.

    IMPORTANT:
    - No Label column is created.
    - No attack category is inferred from the run ID.
    - The extracted flow attributes are appended as-is.
    """
    global MASTER_ROW_COUNT

    if not new_csv_paths:
        return

    dfs = []

    for csv_file in new_csv_paths:
        run_id = os.path.basename(csv_file).replace("_flows.csv", "")

        if run_id in COMBINED_RUN_IDS:
            continue

        try:
            df = _load_csv(csv_file)

            if df is not None:
                dfs.append(df)
                COMBINED_RUN_IDS.add(run_id)

        except Exception as e:
            print(f"[!] Warning reading {csv_file}: {e}")

    if not dfs:
        return

    new_df = pd.concat(dfs, ignore_index=True)

    write_header = not (
        os.path.exists(OUTPUT_CSV)
        and os.path.getsize(OUTPUT_CSV) > 0
    )

    new_df.to_csv(
        OUTPUT_CSV,
        mode="a",
        header=write_header,
        index=False
    )

    MASTER_ROW_COUNT += len(new_df)

    print("\n==================================================")
    print(f"[OK] MASTER DATASET UPDATED: {OUTPUT_CSV}")
    print(
        f"[OK] Added {len(new_df)} new flows from "
        f"{len(dfs)} runs (total: {MASTER_ROW_COUNT} flows)"
    )
    print("[OK] No Label column was added.")
    print("==================================================\n")


def extract_all_parallel(extraction_executor):
    """Main extraction cycle: threaded downloads, then process-pool feature extraction."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    runs = fetch_completed_runs()
    if not runs:
        print("Waiting for completed runs from MMT Studio...")
        return

    # Stage 1: downloads are I/O-bound -> threads are the right tool here.
    ready_run_ids = []
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        futures = [executor.submit(download_step, run) for run in runs]
        for future in as_completed(futures):
            try:
                run_id = future.result()
                if run_id:
                    ready_run_ids.append(run_id)
            except Exception as e:
                print(f"[!] Download worker error: {e}")

    # Stage 2: extraction is CPU-bound -> use a persistent process pool so we
    # don't spawn/tear down workers every 5s, and so scapy state never
    # leaks between concurrent extractions.
    new_csv_paths = []
    if ready_run_ids:
        futures = [extraction_executor.submit(extraction_step, run_id) for run_id in ready_run_ids]
        for future in as_completed(futures):
            try:
                csv_path = future.result()
                if csv_path:
                    new_csv_paths.append(csv_path)
            except Exception as e:
                print(f"[!] Extraction worker error: {e}")

    # Only append what's new this cycle - never rescan/rewrite the whole dataset.
    append_new_flows_to_master(new_csv_paths)


def main():
    import sys

    if "--backfill" in sys.argv:
        print("\n==================================================")
        print(" Backfill mode: extracting existing pcaps only ")
        print("==================================================\n")
        backfill_existing_pcaps()
        return

    print("\n==================================================")
    print(" Parallel Flow Extractor Active ")
    print(f" Polling MMT Studio every 5s "
          f"({DOWNLOAD_WORKERS} download threads, {EXTRACTION_WORKERS} extraction processes)")
    print(" Press Ctrl+C to stop")
    print("==================================================\n")

    bootstrap_master_dataset()

    # One long-lived process pool for the whole daemon's life, instead of
    # creating/destroying one every cycle.
    with ProcessPoolExecutor(max_workers=EXTRACTION_WORKERS) as extraction_executor:
        try:
            while True:
                extract_all_parallel(extraction_executor)
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] Stopping Flow Extractor daemon.")


if __name__ == "__main__":
    main()
