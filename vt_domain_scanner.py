#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal Domain Scanner v6
Multi-threaded domain reputation scanning with configurable proxy backend

Note: Tor support was removed. VirusTotal is hosted on Google Cloud
infrastructure, which blocks nearly all known Tor exit nodes at the
network edge (HTTP 403 before reaching the API). Testing confirmed
100% failure rate across multiple Tor circuits, so it provided no
practical benefit.
"""

import os
import sys
import csv
import json
import time
import random
import threading
import signal
import urllib.request
import urllib.error
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = _NoColor()
    Style = _NoColor()

# Semantic color shortcuts used throughout console output
COLOR_CLEAN = Fore.GREEN
COLOR_SUSPICIOUS = Fore.YELLOW
COLOR_MALICIOUS = Fore.RED
COLOR_ERROR = Fore.MAGENTA
COLOR_INFO = Fore.CYAN
COLOR_WARNING = Fore.YELLOW
COLOR_RESET = Style.RESET_ALL

def malicious_color(count):
    """Return an escalating color based on malicious detection count"""
    if count >= 10:
        return Fore.RED + Style.BRIGHT
    elif count >= 5:
        return Fore.RED
    else:
        return Fore.LIGHTRED_EX if COLOR_ENABLED else Fore.RED

# ============================================================================
# EARLY SIGNAL HANDLING (registered before anything else so Ctrl+C always works,
# even during the proxy-mode menu or proxy validation phase)
# ============================================================================

should_exit = False
is_paused = False

def signal_handler(sig, frame):
    """Ctrl+C handler - forcefully exit"""
    global should_exit
    print("\n\n[INTERRUPT] Ctrl+C received; saving state and exiting...", flush=True)
    should_exit = True
    time.sleep(0.3)
    
    try:
        if 'results' in globals() and results:
            save_results()
            save_checkpoint()
            print("[OK] State saved", flush=True)
    except Exception:
        pass
    
    print("[EXIT] Goodbye!", flush=True)
    os._exit(0)  # Force exit immediately, bypasses blocked threads

signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, signal_handler)  # Windows Ctrl+Break

# ============================================================================
# CONFIGURATION & INITIALIZATION
# ============================================================================


def load_api_keys(filepath='api_keys.env'):
    """Load API keys from file (one per line)"""
    keys = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                key = line.strip()
                if key and len(key) > 20:
                    keys.append(key)
        
        if not keys:
            print("[ERROR] No valid keys found in api_keys.env")
            sys.exit(1)
        
        print(f"[OK] Loaded {len(keys)} API keys")
        return keys
    except FileNotFoundError:
        print(f"[ERROR] api_keys.env not found")
        sys.exit(1)

API_KEYS = load_api_keys()

# Public raw proxy list sources (plain text, one "ip:port" per line)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
]

# Endpoint used to validate a proxy is alive and forwarding traffic
PROXY_TEST_URL = "https://www.virustotal.com/api/v3/domains/google.com"
PROXY_FETCH_TIMEOUT = 10   # seconds per source download
PROXY_TEST_TIMEOUT = 6     # seconds per proxy validation
PROXY_VALIDATION_WORKERS = 30  # parallel validation threads
PROXY_MAX_CANDIDATES = 500  # cap how many raw candidates we bother testing

# Live, validated proxies populated by validate_and_build_proxy_pool()
FREE_PROXY_LIST = []

# Dead proxy tracking (per execution session)
dead_proxies = set()
proxy_lock = threading.Lock()

def fetch_proxy_candidates():
    """Download candidate proxies (ip:port) from public raw lists"""
    candidates = set()
    
    for source_url in PROXY_SOURCES:
        try:
            req = urllib.request.Request(source_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=PROXY_FETCH_TIMEOUT) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
            
            count_before = len(candidates)
            for line in text.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                # Expect format ip:port
                parts = line.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    candidates.add(f"http://{line}")
            
            added = len(candidates) - count_before
            print(f"[OK] {source_url.split('/')[2]}: +{added} candidates")
        
        except Exception as err:
            print(f"[WARNING] Failed to fetch {source_url.split('/')[2]}: {str(err)[:60]}")
            continue
    
    return list(candidates)

def validate_single_proxy(proxy):
    """Test a single proxy against VirusTotal; return proxy if working, else None"""
    try:
        proxy_handler = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
        opener = urllib.request.build_opener(proxy_handler)
        
        req = urllib.request.Request(
            PROXY_TEST_URL,
            headers={"User-Agent": "Mozilla/5.0", "x-apikey": "0" * 64}
        )
        
        # We only care that the proxy connects and forwards the TLS/HTTP request;
        # even a 401 (bad dummy key) proves the proxy successfully reached VirusTotal.
        opener.open(req, timeout=PROXY_TEST_TIMEOUT)
        return proxy
    
    except urllib.error.HTTPError as http_err:
        # Any HTTP response (401, 403, 404...) means the proxy IS working -
        # it successfully relayed the request and got a real response back
        if http_err.code in [401, 403, 404, 429]:
            return proxy
        return None
    
    except Exception:
        return None

def validate_and_build_proxy_pool():
    """Fetch fresh proxy candidates and validate them in parallel before scanning starts"""
    print("\n" + "="*80)
    print("PROXY POOL SETUP")
    print("="*80)
    
    print("\n[*] Fetching proxy candidates from public sources...\n")
    candidates = fetch_proxy_candidates()
    
    if not candidates:
        print("\n[ERROR] No proxy candidates could be fetched from any source")
        print("[INFO] Falling back to DIRECT mode is recommended")
        return []
    
    if len(candidates) > PROXY_MAX_CANDIDATES:
        random.shuffle(candidates)
        candidates = candidates[:PROXY_MAX_CANDIDATES]
    
    print(f"\n[OK] Total unique candidates: {len(candidates)}")
    print(f"[*] Validating proxies against VirusTotal (timeout {PROXY_TEST_TIMEOUT}s each, "
          f"{PROXY_VALIDATION_WORKERS} parallel workers)...")
    print("[*] This may take 1-3 minutes depending on candidate count\n")
    
    working = []
    tested = 0
    last_reported_percent = -1
    
    with ThreadPoolExecutor(max_workers=PROXY_VALIDATION_WORKERS) as executor:
        futures = {executor.submit(validate_single_proxy, p): p for p in candidates}
        
        for future in as_completed(futures):
            if should_exit:
                break
            
            tested += 1
            result = future.result()
            if result:
                working.append(result)
            
            percent = tested * 100 // len(candidates)
            if percent != last_reported_percent and percent % 5 == 0:
                print(f"\r[*] Validated: {tested}/{len(candidates)} ({percent}%) | "
                      f"Working: {len(working)}", end='', flush=True)
                last_reported_percent = percent
    
    print(f"\r[*] Validated: {tested}/{len(candidates)} (100%) | Working: {len(working)}" + " "*20)
    
    if not working:
        print("\n[ERROR] No working proxies found among candidates")
        print("[INFO] Consider using DIRECT mode instead")
    else:
        print(f"\n[OK] Proxy pool ready: {len(working)} working proxies")
    
    return working

# ============================================================================
# PROXY MODE SELECTION
# ============================================================================

def show_proxy_selection_menu():
    """Interactive proxy backend selection"""
    print("\n" + "="*80)
    print("PROXY BACKEND CONFIGURATION")
    print("="*80)
    
    print("\n[1] DIRECT")
    print("    Processing rate: 5-6 domains/second")
    print("    Description: No proxy; direct connection to VirusTotal")
    print("    Dependencies: None")
    print("    Behavior: Single source IP; rate limiting possible after ~1000 requests")
    
    print("\n[2] OPEN_PROXY")
    print("    Processing rate: 2-3 domains/second (slower startup: proxies validated first)")
    print("    Description: Fetch + validate live proxies before scanning, then rotate")
    print("    Dependencies: None (internet access to fetch proxy lists)")
    print("    Behavior: Only proxies confirmed working against VirusTotal are used;")
    print("              dead proxies encountered mid-scan are auto-skipped")
    
    print("\n" + "-"*80)
    
    while True:
        try:
            choice = input("Select mode [1-2]: ").strip()
            if choice in ["1", "2"]:
                mode_map = {"1": "DIRECT", "2": "OPEN_PROXY"}
                selected_mode = mode_map[choice]
                
                print(f"\n[OK] Selected: {selected_mode}")
                return selected_mode
            else:
                print("[ERROR] Invalid selection. Enter 1 or 2.")
        except KeyboardInterrupt:
            print("\n[ABORT] User interrupted")
            sys.exit(0)

PROXY_MODE = show_proxy_selection_menu()

if PROXY_MODE == "OPEN_PROXY":
    FREE_PROXY_LIST = validate_and_build_proxy_pool()
    
    if not FREE_PROXY_LIST:
        fallback = input("\n[?] No working proxies found. Switch to DIRECT mode? [Y/n]: ").strip().lower()
        if fallback != 'n':
            PROXY_MODE = "DIRECT"
            print("[OK] Switched to DIRECT mode")



# ============================================================================
# CONSTANTS
# ============================================================================

VT_API_URL = "https://www.virustotal.com/api/v3/domains"
REQUEST_TIMEOUT = 15  # Per request timeout
MAX_RETRIES = 3  # Retry attempts per domain (including proxy rotation)
RATE_LIMIT_COOLDOWN = 300  # seconds (429 response)
DELAY_BETWEEN_REQUESTS = 0.2  # seconds
NUM_THREADS = 4
RESUME_FILE = "vt_resume.json"

# Maximum wait time for a single domain scan (timeout failsafe)
DOMAIN_SCAN_TIMEOUT = 60  # seconds

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
]

# ============================================================================
# GLOBAL STATE
# ============================================================================

results = []
lock = threading.Lock()
key_cooldown = {key: 0.0 for key in API_KEYS}
key_request_count = {key: 0 for key in API_KEYS}
key_error_count = {key: 0 for key in API_KEYS}
processed_domains = set()
failed_domains = {}  # domain -> reason
start_time = datetime.now()
total_domains = 0
current_key_index = 0
current_proxy_index = 0
total_requests_made = 0  # Global request counter (across all keys)

# ============================================================================
# PERSISTENCE
# ============================================================================

def save_checkpoint():
    """Persist execution state"""
    checkpoint = {
        "timestamp": datetime.now().isoformat(),
        "mode": PROXY_MODE,
        "processed_domains": list(processed_domains),
        "failed_domains": failed_domains,
        "results": results,
        "dead_proxies": list(dead_proxies),
        "key_stats": {
            "request_counts": key_request_count,
            "error_counts": key_error_count,
            "cooldown_times": {k: v for k, v in key_cooldown.items() if v > time.time()}
        }
    }
    
    with open(RESUME_FILE, 'w', encoding='utf-8') as f:
        json.dump(checkpoint, f, indent=2)

def load_checkpoint():
    """Restore execution state"""
    global processed_domains, failed_domains, results, key_request_count, key_error_count, start_time, dead_proxies
    
    if not os.path.exists(RESUME_FILE):
        return False
    
    try:
        with open(RESUME_FILE, 'r', encoding='utf-8') as f:
            checkpoint = json.load(f)
        
        processed_domains = set(checkpoint.get("processed_domains", []))
        failed_domains = checkpoint.get("failed_domains", {})
        results = checkpoint.get("results", [])
        dead_proxies = set(checkpoint.get("dead_proxies", []))
        key_request_count = checkpoint.get("key_stats", {}).get("request_counts", key_request_count)
        key_error_count = checkpoint.get("key_stats", {}).get("error_counts", key_error_count)
        
        print(f"[OK] Restored checkpoint: {len(processed_domains)} domains processed")
        if dead_proxies:
            print(f"[OK] Dead proxies recorded: {len(dead_proxies)}")
        return True
    except (json.JSONDecodeError, KeyError):
        print("[WARNING] Checkpoint corrupted; starting fresh")
        return False

# ============================================================================
# SIGNAL HANDLING & PAUSE MANAGEMENT
# ============================================================================

def pause_for_recovery():
    """Pause scanning and wait for user to refresh IP/connection"""
    global is_paused
    
    is_paused = True
    
    print("\n" + "="*80)
    print(f"{COLOR_WARNING}RATE LIMIT DETECTED - SCANNING PAUSED{COLOR_RESET}")
    print("="*80)
    print(f"\n[!] {total_requests_made} requests made to VirusTotal")
    print("[!] Rate limiting detected - source IP/connection is restricted")
    print("\nTo continue scanning, you need to refresh your connection:\n")
    
    if PROXY_MODE == "DIRECT":
        print("[ACTION REQUIRED]")
        print("  1. Disconnect from VPN (if using one)")
        print("  2. Change your IP address:")
        print("     - Restart modem/router (wait 5-10 minutes for new IP)")
        print("     - OR use VPN/Proxy service")
        print("     - OR use different network")
        print("  3. Verify new IP: https://www.whatsmyip.com/")
        print("  4. Return here and press ENTER to resume")
    
    elif PROXY_MODE == "OPEN_PROXY":
        print("[ACTION REQUIRED]")
        print("  1. Script will automatically rotate through different proxies")
        print("  2. If all proxies exhausted, refresh or add new proxies")
        print("  3. Return here and press ENTER to resume")
    
    print("\n" + "-"*80)
    
    try:
        input("[WAITING] Press ENTER when ready to resume: ")
    except KeyboardInterrupt:
        print("\n[ABORT] User interrupted")
        sys.exit(0)
    
    print("[*] Resuming scan...\n")
    is_paused = False

# ============================================================================
# PROXY MANAGEMENT
# ============================================================================

MIN_LIVE_PROXIES_THRESHOLD = 5  # Trigger background replenishment below this count
proxy_pool_refilling = False    # Guard so only one replenishment runs at a time
proxy_pool_refill_lock = threading.Lock()

def live_proxy_count():
    """Number of proxies in the pool that are not marked dead"""
    with proxy_lock:
        return len([p for p in FREE_PROXY_LIST if p not in dead_proxies])

def replenish_proxy_pool(target_new=40, background=True):
    """Fetch and validate a fresh batch of proxies, extending the live pool.
    
    Called automatically when the live proxy count drops below
    MIN_LIVE_PROXIES_THRESHOLD, so long scans never run out of proxies.
    """
    global proxy_pool_refilling
    
    with proxy_pool_refill_lock:
        if proxy_pool_refilling:
            return  # Another replenishment is already in progress
        proxy_pool_refilling = True
    
    try:
        print(f"\n[PROXY POOL] Live proxies low ({live_proxy_count()} remaining); "
              f"fetching a fresh batch in the background...\n")
        
        candidates = fetch_proxy_candidates()
        
        with proxy_lock:
            known = set(FREE_PROXY_LIST) | dead_proxies
        candidates = [c for c in candidates if c not in known]
        
        if not candidates:
            print("[PROXY POOL] No new candidates found from sources")
            return
        
        random.shuffle(candidates)
        candidates = candidates[:PROXY_MAX_CANDIDATES]
        
        new_working = []
        with ThreadPoolExecutor(max_workers=PROXY_VALIDATION_WORKERS) as executor:
            futures = {executor.submit(validate_single_proxy, p): p for p in candidates}
            for future in as_completed(futures):
                if should_exit:
                    break
                result = future.result()
                if result:
                    new_working.append(result)
                if len(new_working) >= target_new:
                    break
        
        with proxy_lock:
            for p in new_working:
                if p not in FREE_PROXY_LIST:
                    FREE_PROXY_LIST.append(p)
        
        print(f"\n[PROXY POOL] Replenished: +{len(new_working)} new working proxies "
              f"(live pool now: {live_proxy_count()})\n")
    
    except Exception as err:
        print(f"[PROXY POOL] Replenishment failed: {str(err)[:80]}")
    
    finally:
        with proxy_pool_refill_lock:
            proxy_pool_refilling = False

def get_available_proxy():
    """Get next available proxy (skip dead ones); auto-replenish pool when low"""
    global current_proxy_index
    
    live_count = live_proxy_count()
    
    # Pool running low: kick off a background refill (non-blocking, scan continues
    # with remaining live proxies while new ones are fetched/validated)
    if live_count <= MIN_LIVE_PROXIES_THRESHOLD and not proxy_pool_refilling:
        threading.Thread(target=replenish_proxy_pool, daemon=True).start()
    
    with proxy_lock:
        if not FREE_PROXY_LIST:
            return None
        
        attempts = 0
        max_attempts = len(FREE_PROXY_LIST) * 2
        
        while attempts < max_attempts:
            proxy = FREE_PROXY_LIST[current_proxy_index % len(FREE_PROXY_LIST)]
            current_proxy_index += 1
            
            if proxy not in dead_proxies:
                return proxy
            
            attempts += 1
    
    # Pool fully exhausted (every known proxy is dead) - block and force an
    # immediate synchronous replenishment rather than silently falling back
    print("\n[WARNING] All proxies in the pool are dead. Fetching a new batch now "
          "(this will pause scanning briefly)...\n")
    replenish_proxy_pool(target_new=20, background=False)
    
    with proxy_lock:
        live = [p for p in FREE_PROXY_LIST if p not in dead_proxies]
        if live:
            return live[0]
    
    print("\n[ERROR] Could not find any working proxies after replenishment attempt.")
    print("[INFO] Falling back to direct connection for this request.\n")
    return None

def mark_proxy_dead(proxy):
    """Mark proxy as dead (connection failed)"""
    with proxy_lock:
        dead_proxies.add(proxy)
        remaining = len([p for p in FREE_PROXY_LIST if p not in dead_proxies])
        print(f"{COLOR_WARNING}[PROXY] Marked dead: {proxy} ({remaining} live remaining){COLOR_RESET}")

def get_proxy_config():
    """Return proxy handler based on selected mode"""
    if PROXY_MODE == "DIRECT":
        return None
    
    elif PROXY_MODE == "OPEN_PROXY":
        return get_available_proxy()
    
    return None

# ============================================================================
# DOMAIN PROCESSING
# ============================================================================

def sanitize_domain(domain_input):
    """Normalize domain string"""
    domain = domain_input.strip().lower()
    
    # Remove protocol
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    
    # Remove www subdomain
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Remove trailing slash
    domain = domain.rstrip("/")
    
    return domain

def validate_domain(domain_input):
    """Validate domain format"""
    domain = sanitize_domain(domain_input)
    
    # Minimum length, no spaces, no paths
    if not domain or len(domain) < 3 or " " in domain or "/" in domain:
        return None
    
    return domain

def load_domain_list(filepath='domains.txt'):
    """Load domain list from file"""
    domains = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                domain = validate_domain(line)
                if domain:
                    domains.append(domain)
    except FileNotFoundError:
        print(f"[ERROR] {filepath} not found")
        sys.exit(1)
    
    return list(set(domains))  # Remove duplicates

# ============================================================================
# API INTERACTION
# ============================================================================

def select_available_key():
    """Select next non-cooldown API key"""
    global current_key_index
    current_time = time.time()
    
    # Attempt to find available key
    for i in range(len(API_KEYS)):
        idx = (current_key_index + i) % len(API_KEYS)
        key = API_KEYS[idx]
        
        if key_cooldown[key] <= current_time:
            current_key_index = (idx + 1) % len(API_KEYS)
            return key
    
    # All keys in cooldown; wait for next available
    min_cooldown_key = min(API_KEYS, key=lambda k: key_cooldown[k])
    wait_time = key_cooldown[min_cooldown_key] - current_time
    print(f"{COLOR_WARNING}[WAIT] All keys in cooldown; resuming in {wait_time:.0f}s{COLOR_RESET}")
    time.sleep(min(wait_time + 1.0, 60))
    return select_available_key()

def query_vt_api(domain, api_key, proxy=None, retry_count=0):
    """Query VirusTotal API for domain reputation
    
    Args:
        domain: Target domain
        api_key: VirusTotal API key
        proxy: Proxy address (HTTP/HTTPS) or None for direct connection
        retry_count: Current retry attempt
    
    Returns:
        dict: API response or None on failure
    
    Retry logic:
        - HTTP 429 (rate limit): Pause scanning, wait for user to refresh connection
        - HTTP 4xx (auth/not found): Don't retry
        - HTTP 5xx / timeout / connection error: Retry with different proxy
        - Dead proxy: Mark dead, retry with next proxy
    """
    if retry_count >= MAX_RETRIES:
        with lock:
            failed_domains[domain] = f"Max retries exceeded ({MAX_RETRIES})"
        return None
    
    try:
        url = f"{VT_API_URL}/{domain}"
        
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": api_key,
                "User-Agent": random.choice(USER_AGENTS),
            }
        )
        
        # Configure proxy if specified
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy,
                'https': proxy
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
        
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            data = response.read().decode('utf-8')
            
            with lock:
                key_request_count[api_key] += 1
            
            return json.loads(data)
    
    except urllib.error.HTTPError as http_err:
        with lock:
            key_request_count[api_key] += 1
        
        if http_err.code == 429:
            # Rate limited - trigger pause for IP/connection refresh
            global total_requests_made
            
            with lock:
                key_cooldown[api_key] = time.time() + RATE_LIMIT_COOLDOWN
                key_error_count[api_key] += 1
                total_requests_made = sum(key_request_count.values())
            
            # Pause scanning and wait for user to refresh connection
            pause_for_recovery()
            
            return None
        
        elif http_err.code == 404:
            # Domain not found in VT database (valid response)
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0}
                    }
                }
            }
        
        elif http_err.code in [401, 403]:
            # Invalid/revoked key - don't retry
            with lock:
                key_error_count[api_key] += 10
            return None
        
        elif http_err.code >= 500:
            # Server error - retry with different proxy
            with lock:
                key_error_count[api_key] += 1
            
            if proxy:
                mark_proxy_dead(proxy)
            
            time.sleep(1)
            next_proxy = get_proxy_config()
            return query_vt_api(domain, api_key, next_proxy, retry_count + 1)
        
        else:
            # Other HTTP error - retry
            with lock:
                key_error_count[api_key] += 1
            
            time.sleep(1)
            next_proxy = get_proxy_config()
            return query_vt_api(domain, api_key, next_proxy, retry_count + 1)
    
    except (urllib.error.URLError, socket.timeout, TimeoutError) as conn_err:
        """Connection errors: timeout, proxy down, network issue"""
        with lock:
            key_error_count[api_key] += 1
        
        # Mark proxy as dead if applicable
        if proxy:
            mark_proxy_dead(proxy)
        
        # Retry with different proxy
        time.sleep(1)
        next_proxy = get_proxy_config()
        return query_vt_api(domain, api_key, next_proxy, retry_count + 1)
    
    except Exception as err:
        """Unexpected errors"""
        with lock:
            key_error_count[api_key] += 1
            failed_domains[domain] = f"Unexpected error: {str(err)[:50]}"
        
        return None

# ============================================================================
# SCANNING
# ============================================================================

def scan_domain(domain, force_direct=False, is_retry=False):
    """Scan single domain with timeout failsafe
    
    Args:
        domain: Domain to scan
        force_direct: If True, bypass proxy config and connect directly
                      (used for the post-scan retry pass on failed domains)
        is_retry: If True, domain is allowed to be re-processed even if
                  already marked in processed_domains
    """
    global is_paused
    
    if should_exit:
        return
    
    # Wait if paused due to rate limit
    while is_paused:
        time.sleep(0.5)
        if should_exit:
            return
    
    domain = sanitize_domain(domain)
    
    with lock:
        if not is_retry:
            if domain in processed_domains:
                return
            processed_domains.add(domain)
    
    time.sleep(DELAY_BETWEEN_REQUESTS)
    
    scan_start = time.time()
    
    api_key = select_available_key()
    proxy = None if force_direct else get_proxy_config()
    
    try:
        response = query_vt_api(domain, api_key, proxy)
    except Exception as err:
        response = None
        with lock:
            failed_domains[domain] = f"Scan exception: {str(err)[:50]}"
    
    # Check scan timeout
    elapsed = time.time() - scan_start
    if elapsed > DOMAIN_SCAN_TIMEOUT:
        print(f"{COLOR_ERROR}[TIMEOUT] {domain} exceeded {DOMAIN_SCAN_TIMEOUT}s limit{COLOR_RESET}")
        with lock:
            failed_domains[domain] = f"Scan timeout ({elapsed:.0f}s > {DOMAIN_SCAN_TIMEOUT}s)"
        return
    
    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "status": "error",
        "malicious_count": 0,
        "suspicious_count": 0,
        "undetected_count": 0,
        "threat_names": [],
        "last_analysis_date": None,
        "api_key_hash": api_key[:8],
        "proxy_used": proxy if proxy else "NONE",
        "scan_duration_sec": elapsed,
    }
    
    if response and "data" in response:
        try:
            attributes = response["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result["status"] = "success"
            result["malicious_count"] = stats.get("malicious", 0)
            result["suspicious_count"] = stats.get("suspicious", 0)
            result["undetected_count"] = stats.get("undetected", 0)
            result["last_analysis_date"] = attributes.get("last_analysis_date")
            
            # Extract threat names
            analysis_results = attributes.get("last_analysis_results", {})
            threats = set()
            for vendor, vendor_result in analysis_results.items():
                if vendor_result.get("category") in ["malicious", "suspicious"]:
                    if "result" in vendor_result:
                        threats.add(vendor_result["result"])
            result["threat_names"] = list(threats)[:5]
        
        except (KeyError, TypeError):
            pass
    
    with lock:
        if is_retry:
            # Remove the previous failed result entry for this domain before appending the new one
            results[:] = [r for r in results if r["domain"] != domain]
        results.append(result)
        
        if result["status"] == "success":
            # Successful retry: clear from failed_domains log
            failed_domains.pop(domain, None)
    
    # Console output
    prefix = "[RETRY] " if is_retry else ""
    if result["malicious_count"] > 0:
        color = malicious_color(result["malicious_count"])
        print(f"  {color}{prefix}[MALICIOUS] {domain} ({result['malicious_count']} detections){COLOR_RESET}")
    elif result["suspicious_count"] > 0:
        print(f"  {COLOR_SUSPICIOUS}{prefix}[SUSPICIOUS] {domain} ({result['suspicious_count']} detections){COLOR_RESET}")
    elif result["status"] == "success":
        print(f"  {COLOR_CLEAN}{prefix}[CLEAN] {domain}{COLOR_RESET}")
    else:
        print(f"  {COLOR_ERROR}{prefix}[ERROR] {domain}{COLOR_RESET}")

def worker_thread(domain_queue, thread_id):
    """Worker thread for domain scanning"""
    while not should_exit:
        try:
            domain = domain_queue.pop(0)
        except (IndexError, AttributeError):
            break
        
        scan_domain(domain)
        
        with lock:
            processed_count = len(processed_domains)
        
        if processed_count % 100 == 0 and processed_count > 0:
            elapsed = (datetime.now() - start_time).total_seconds()
            rate = processed_count / elapsed if elapsed > 0 else 0
            eta_seconds = (total_domains - processed_count) / rate if rate > 0 else 0
            
            print(f"\n[THREAD-{thread_id}] Progress: {processed_count}/{total_domains} | "
                  f"Rate: {rate:.2f} domain/s | ETA: {eta_seconds:.0f}s")
            
            if dead_proxies and PROXY_MODE == "OPEN_PROXY":
                print(f"[THREAD-{thread_id}] Proxy pool: {live_proxy_count()} live / "
                      f"{len(dead_proxies)} dead\n")
            else:
                print()

def retry_failed_domains(max_rounds=2):
    """Retry domains that ended with status 'error' using a direct connection.
    
    Proxies (especially free public ones) are unreliable and often cause
    transient failures unrelated to the domain itself. This pass re-queries
    every failed domain directly (bypassing proxy rotation) for a few rounds,
    since DIRECT mode has proven far more reliable than rotating proxies.
    """
    for round_num in range(1, max_rounds + 1):
        if should_exit:
            return
        
        error_domains = [r["domain"] for r in results if r["status"] == "error"]
        
        if not error_domains:
            return
        
        print("\n" + "="*80)
        print(f"RETRY PASS {round_num}/{max_rounds} - {len(error_domains)} failed domain(s)")
        print("="*80)
        print("[*] Retrying with direct connection (bypassing proxies)...\n")
        
        with lock:
            for d in error_domains:
                processed_domains.discard(d)
        
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = [executor.submit(scan_domain, d, True, True) for d in error_domains]
            for future in as_completed(futures):
                if should_exit:
                    break
                future.result()
        
        remaining = len([r for r in results if r["status"] == "error"])
        print(f"\n[OK] Retry pass {round_num} complete. Remaining errors: {remaining}")
        
        if remaining == 0:
            return

# ============================================================================
# REPORTING
# ============================================================================

def save_results():
    """Export results to CSV and JSON"""
    if not results:
        return
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # CSV export
    csv_filename = f"vt_scan_results_{timestamp}.csv"
    try:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                "domain", "timestamp", "status", "malicious_count", "suspicious_count",
                "undetected_count", "threat_names", "last_analysis_date", "api_key_hash",
                "proxy_used", "scan_duration_sec"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in sorted(results, 
                               key=lambda x: (x["malicious_count"], x["suspicious_count"]), 
                               reverse=True):
                result_copy = result.copy()
                result_copy["threat_names"] = "; ".join(result_copy["threat_names"])
                writer.writerow(result_copy)
        
        print(f"[OK] CSV export: {csv_filename}")
    except Exception as err:
        print(f"[ERROR] CSV export failed: {err}")
    
    # JSON export
    json_filename = f"vt_scan_results_{timestamp}.json"
    try:
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"[OK] JSON export: {json_filename}")
    except Exception as err:
        print(f"[ERROR] JSON export failed: {err}")
    
    # Failed domains log
    if failed_domains:
        failed_filename = f"vt_failed_domains_{timestamp}.json"
        try:
            with open(failed_filename, 'w', encoding='utf-8') as f:
                json.dump(failed_domains, f, indent=2, ensure_ascii=False)
            
            print(f"[OK] Failed domains: {failed_filename}")
        except Exception as err:
            print(f"[ERROR] Failed domains export failed: {err}")

def print_summary():
    """Print execution summary"""
    elapsed = (datetime.now() - start_time).total_seconds()
    
    print("\n" + "="*80)
    print("SCAN RESULTS SUMMARY")
    print("="*80)
    
    if not results:
        print("[WARNING] No results to summarize")
        return
    
    clean = len([r for r in results if r["malicious_count"] == 0 and r["suspicious_count"] == 0])
    suspicious = len([r for r in results if r["suspicious_count"] > 0 and r["malicious_count"] == 0])
    malicious = len([r for r in results if r["malicious_count"] > 0])
    errors = len([r for r in results if r["status"] == "error"])
    
    print(f"\nCLASSIFICATION DISTRIBUTION:")
    print(f"  {COLOR_CLEAN}Clean:       {clean:5d} ({clean*100//len(results):3d}%){COLOR_RESET}")
    print(f"  {COLOR_SUSPICIOUS}Suspicious:  {suspicious:5d} ({suspicious*100//len(results):3d}%){COLOR_RESET}")
    print(f"  {COLOR_MALICIOUS}Malicious:   {malicious:5d} ({malicious*100//len(results):3d}%){COLOR_RESET}")
    print(f"  {COLOR_ERROR}Errors:      {errors:5d} ({errors*100//len(results):3d}%){COLOR_RESET}")
    print(f"  Total:       {len(results):5d}")
    
    print(f"\nPERFORMANCE METRICS:")
    print(f"  Duration:    {elapsed:.1f}s ({elapsed/60:.1f}m)")
    if len(results) > 0:
        print(f"  Avg rate:    {len(results)/elapsed:.2f} domain/s")
    
    if failed_domains:
        print(f"\nFAILED DOMAINS: {len(failed_domains)}")
    
    if dead_proxies and PROXY_MODE == "OPEN_PROXY":
        print(f"\nDEAD PROXIES: {len(dead_proxies)}/{len(FREE_PROXY_LIST)}")
    
    print(f"\nEXECUTION PARAMETERS:")
    print(f"  Mode:        {PROXY_MODE}")
    print(f"  Threads:     {NUM_THREADS}")
    print(f"  Timeout:     {DOMAIN_SCAN_TIMEOUT}s per domain")
    print(f"  Keys used:   {len([k for k in API_KEYS if key_request_count[k] > 0])}")
    
    print("="*80 + "\n")

# ============================================================================
# MAIN
# ============================================================================

def main():
    global total_domains
    
    print("\n" + "="*80)
    print("VirusTotal Domain Scanner v6")
    print(f"Mode: {PROXY_MODE} | Threads: {NUM_THREADS} | Request Delay: {DELAY_BETWEEN_REQUESTS}s")
    print("="*80)
    
    # Load checkpoint
    print("\n[*] Checking checkpoint...")
    load_checkpoint()
    
    # Load domain list
    domain_file = "domains.txt"
    if not os.path.exists(domain_file):
        print(f"[ERROR] {domain_file} not found")
        sys.exit(1)
    
    all_domains = load_domain_list(domain_file)
    pending_domains = [d for d in all_domains if d not in processed_domains]
    total_domains = len(all_domains)
    
    print(f"\n[OK] Domain inventory:")
    print(f"     Total:     {total_domains}")
    print(f"     Processed: {len(processed_domains)}")
    print(f"     Pending:   {len(pending_domains)}")
    print(f"\n[OK] API keys: {len(API_KEYS)}")
    
    # Estimate runtime
    estimated_hours = (len(pending_domains) * DELAY_BETWEEN_REQUESTS) / 3600
    print(f"[INFO] Estimated runtime: {estimated_hours:.2f} hours\n")
    
    print("[*] Starting scan (Ctrl+C to suspend)\n")
    time.sleep(1)
    
    # Launch worker threads (daemon=True so the process can exit immediately on Ctrl+C)
    threads = []
    for thread_id in range(NUM_THREADS):
        t = threading.Thread(target=worker_thread, args=(pending_domains, thread_id + 1), daemon=True)
        t.start()
        threads.append(t)
    
    # Wait for completion using short timeouts so the main thread stays responsive
    # to KeyboardInterrupt/signal handling instead of blocking indefinitely
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.3)
                if should_exit:
                    break
            if should_exit:
                break
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    
    # Retry any domains that failed (proxy/timeout errors) using direct connection
    if not should_exit:
        retry_failed_domains()
    
    # Report and save
    print_summary()
    
    if results:
        save_results()
        save_checkpoint()
    
    print("[OK] Scan complete\n")

if __name__ == "__main__":
    main()
