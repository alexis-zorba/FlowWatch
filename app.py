from flask import Flask, jsonify, send_from_directory
import psutil, time, os

app = Flask(__name__, static_folder="static")

# Storico per delta interfacce e processi
_last_iface = {}
_last_proc  = {}

# Aggiunge header CSP per permettere Chart.js e font inline
@app.after_request
def set_csp(response):
    csp = (
        "default-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; "
        "connect-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data: https://cdn.jsdelivr.net;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# Directory consentite per eseguibili di sistema e browser
ALLOWED_DIRS = [
    os.path.normcase(os.environ.get('ProgramFiles', 'C:\\Program Files')),
    os.path.normcase(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')),
    os.path.normcase(os.environ.get('SystemRoot', 'C:\\Windows'))
]

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

@app.route("/stats")
def stats():
    now = time.time()
    # Interfacce
    total_rx = total_tx = 0.0
    iface_stats = []
    for name, nic in psutil.net_io_counters(pernic=True).items():
        prev_rx, prev_tx, prev_ts = _last_iface.get(name, (nic.bytes_recv, nic.bytes_sent, now))
        elapsed = now - prev_ts or 1
        rx = (nic.bytes_recv - prev_rx) / elapsed
        tx = (nic.bytes_sent - prev_tx) / elapsed
        _last_iface[name] = (nic.bytes_recv, nic.bytes_sent, now)
        iface_stats.append({"name": name, "rx": rx, "tx": tx})
        total_rx += rx
        total_tx += tx

    # Processi: delta e cumulati con verifica path
    proc_list = []
    for p in psutil.process_iter(["pid", "name", "io_counters"]):
        try:
            path = p.exe()
        except Exception:
            path = ""
        ios = p.info.get("io_counters")
        if not ios:
            continue
        cum = ios.read_bytes + ios.write_bytes
        prev_cum, prev_ts = _last_proc.get(p.pid, (cum, now))
        elapsed = now - prev_ts or 1
        delta = (cum - prev_cum) / elapsed
        _last_proc[p.pid] = (cum, now)
        # Verifica se path in directory consentite
        norm_path = os.path.normcase(path)
        suspicious = True
        for d in ALLOWED_DIRS:
            if norm_path.startswith(d):
                suspicious = False
                break
        proc_list.append({
            "pid": p.pid,
            "name": p.info.get("name") or str(p.pid),
            "path": path,
            "suspicious": suspicious,
            "io_delta": delta,
            "io_cum": cum
        })
    # Top 10 delta e cumulati
    procs_delta = sorted(proc_list, key=lambda x: x["io_delta"], reverse=True)[:10]
    procs_cum   = sorted(proc_list, key=lambda x: x["io_cum"],   reverse=True)[:10]

    return jsonify({
        "ts": int(now),
        "ifaces": iface_stats,
        "total_rx": total_rx,
        "total_tx": total_tx,
        "procs_delta": procs_delta,
        "procs_cum": procs_cum
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)