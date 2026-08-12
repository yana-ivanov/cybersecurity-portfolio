from flask import Flask, request, jsonify
import subprocess, tempfile, os, re

app = Flask(__name__)

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def colorize(text):
    """Convert triage output to HTML with color coding."""
    lines = text.split('\n')
    out = []
    for line in lines:
        esc = line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        if '!! MATCH' in line or 'CRITICAL' in line or '!! PAYLOAD' in line:
            out.append(f'<span style="color:#e8374a;font-weight:600">{esc}</span>')
        elif '!!' in line or 'CONFIRMED' in line or 'MACHINE-PRECISE' in line:
            out.append(f'<span style="color:#f07840;font-weight:600">{esc}</span>')
        elif 'PASS' in line or 'clean' in line.lower():
            out.append(f'<span style="color:#2dd4a0">{esc}</span>')
        elif line.startswith('  [') or line.startswith('['):
            out.append(f'<span style="color:#00aeff;font-weight:500">{esc}</span>')
        elif '===' in line or '---' in line:
            out.append(f'<span style="color:#1e2d45">{esc}</span>')
        elif line.strip().startswith('IP Address') or line.strip().startswith('MAC') or line.strip().startswith('Hostname'):
            out.append(f'<span style="color:#94a3b8">{esc}</span>')
        elif 'Severity' in line:
            out.append(f'<span style="color:#e8374a;font-weight:700;font-size:13px">{esc}</span>')
        elif 'Action' in line:
            out.append(f'<span style="color:#f07840;font-weight:600">{esc}</span>')
        else:
            out.append(f'<span style="color:#64748b">{esc}</span>')
    return '\n'.join(out)

PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAVESHAPER.V2 — Triage Tool</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#0d1520;--bg2:#111c2d;--bg3:#162235;--border:rgba(0,174,255,0.12);--border2:rgba(0,174,255,0.25);--blue:#00aeff;--blue-dim:rgba(0,174,255,0.08);--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--red:#e8374a;--orange:#f07840;--green:#2dd4a0;--amber:#f0c040;--mono:"JetBrains Mono",monospace;--display:"Orbitron",monospace;--body:"Inter",sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px}
body{font-family:var(--body);background:var(--bg);color:var(--text);min-height:100vh;line-height:1.6}
.layout{display:grid;grid-template-columns:300px 1fr;grid-template-rows:48px 1fr;height:100vh;overflow:hidden}
.topbar{grid-column:1/-1;background:var(--bg2);border-bottom:1px solid var(--border);padding:.75rem 2rem;display:flex;align-items:center;gap:1rem;z-index:100}
.logo{font-family:var(--display);font-size:1.1rem;font-weight:600;color:var(--blue);letter-spacing:.15em;text-transform:uppercase}
.logo-dot{width:6px;height:6px;border-radius:50%;background:var(--blue);animation:pulse 2s ease-in-out infinite;margin-left:.5rem}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.topbar-badge{font-family:var(--mono);font-size:11px;letter-spacing:.12em;color:var(--blue);border:1px solid var(--border2);padding:.2rem .5rem;border-radius:2px;text-transform:uppercase}
.topbar-right{margin-left:auto;display:flex;gap:.75rem;align-items:center}
.topbar-btn{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;padding:.35rem .85rem;border-radius:2px;cursor:pointer;border:1px solid var(--border2);background:transparent;color:var(--blue);transition:background .2s,opacity .2s;display:flex;align-items:center;gap:.4rem}
.topbar-btn:hover{background:var(--blue-dim)}
.topbar-btn:disabled{opacity:.3;cursor:not-allowed}
.topbar-btn.export{background:var(--blue);color:#0d1520;border-color:var(--blue);font-weight:600}
.topbar-btn.export:hover{opacity:.85}
.topbar-btn.export:disabled{background:transparent;color:var(--text3);border-color:var(--border);font-weight:400;opacity:.35}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);padding:2rem 1.5rem;overflow-y:auto;height:100%}
.sidebar-title{font-family:var(--display);font-size:13px;font-weight:600;color:var(--blue);letter-spacing:.18em;text-transform:uppercase;margin-bottom:.5rem}
.sidebar-subtitle{font-size:14px;color:var(--text2);line-height:20px;margin-bottom:2rem;padding-bottom:2rem;border-bottom:1px solid var(--border)}
.sidebar-section{margin-bottom:2rem;padding-bottom:2rem;border-bottom:1px solid var(--border)}
.sidebar-section:last-child{border-bottom:none;margin-bottom:0}
.sidebar-section-title{font-family:var(--mono);font-size:11px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:1rem}
.sidebar-text{font-size:14px;color:var(--text2);line-height:20px}
.sidebar-text strong{color:var(--text)}
.format-list{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.75rem}
.format-tag{font-family:var(--mono);font-size:11px;color:var(--blue);background:var(--blue-dim);border:1px solid var(--border2);padding:.2rem .5rem;border-radius:2px}
.main{overflow-y:auto;height:100%;padding:1.5rem 2rem;display:flex;flex-direction:column;gap:1.5rem}
.upload-zone{border:2px dashed #94b8d4;border-radius:4px;padding:1.5rem 2rem;text-align:center;cursor:pointer;transition:border-color .2s,background .2s;background:var(--bg2);flex-shrink:0}
.upload-zone:hover,.upload-zone.dragover{border-color:var(--blue);background:var(--blue-dim)}
.upload-title{font-family:var(--display);font-size:14px;font-weight:500;letter-spacing:.12em;color:var(--text);margin-bottom:.5rem}
.upload-subtitle{font-size:14px;color:var(--text2);margin-bottom:1.5rem}
.upload-btn{font-family:var(--mono);font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--blue);background:transparent;border:1px solid var(--border2);padding:.6rem 1.5rem;border-radius:2px;cursor:pointer;transition:background .2s,border-color .2s;pointer-events:none}
.upload-formats{margin-top:1rem;font-family:var(--mono);font-size:11px;color:var(--text3);letter-spacing:.08em}
.file-input{display:none}
.file-info{font-family:var(--mono);font-size:12px;color:var(--blue);text-align:center;padding:.4rem 1rem;background:var(--blue-dim);border:1px solid var(--border2);border-radius:2px;display:none;margin-top:.75rem}
.spinner{display:none;text-align:center;padding:2rem;font-family:var(--mono);font-size:12px;color:var(--text3);letter-spacing:.1em;flex-shrink:0}
.spin{display:inline-block;width:20px;height:20px;border:2px solid var(--border2);border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite;margin-bottom:.75rem}
@keyframes spin{to{transform:rotate(360deg)}}
.result-card{background:var(--bg2);border:1px solid var(--border);border-radius:2px;overflow:hidden;display:none;flex-direction:column;min-height:0}
.result-module-header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;background:var(--bg3);border-bottom:1px solid var(--border);flex-shrink:0}
.result-module-name{font-family:var(--mono);font-size:13px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;color:var(--text);display:flex;align-items:center;gap:.75rem}
.severity-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:4px;font-family:var(--mono);font-size:13px;letter-spacing:.06em;white-space:nowrap;text-transform:uppercase;font-weight:500}
.severity-badge::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor;flex-shrink:0;animation:blink 1.5s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.severity-badge.critical{background:rgba(232,55,74,0.12);color:#e8374a;border:1px solid rgba(232,55,74,0.25)}
.severity-badge.high{background:rgba(240,120,64,0.12);color:#f07840;border:1px solid rgba(240,120,64,0.25)}
.severity-badge.medium{background:rgba(240,192,64,0.12);color:#f0c040;border:1px solid rgba(240,192,64,0.25)}
.severity-badge.low{background:rgba(45,212,160,0.12);color:#2dd4a0;border:1px solid rgba(45,212,160,0.2)}
.result-pre-wrap{overflow-y:auto;max-height:calc(100vh - 340px);padding:1.25rem 1.5rem}
pre{font-family:var(--mono);font-size:14px;line-height:1.9;white-space:pre-wrap;word-break:break-word}
</style>
</head>
<body>
<div class="layout">
<div class="topbar">
  <div class="logo">WAVESHAPER<span style="color:var(--text2)">.V2</span></div>
  <div class="logo-dot"></div>
  <div class="topbar-badge">PCAP Triage</div>
  <div class="topbar-right">
    <button class="topbar-btn" id="refreshBtn" onclick="resetTool()" disabled>&#8635; Refresh</button>
    <button class="topbar-btn export" id="exportBtn" onclick="exportReport()" disabled>&#8595; Export</button>
  </div>
</div>
<div class="sidebar">
  
  
  <div class="sidebar-section">
    <div class="sidebar-section-title">What It Detects</div>
    <div class="sidebar-text">
      <strong>C2 IP connections</strong> — known UNC1069 infrastructure<br><br>
      <strong>Beacon intervals</strong> — machine-precise 60s pattern<br><br>
      <strong>IE8/WinXP User-Agent</strong> — zero legitimate use in 2026<br><br>
      <strong>Stage 2 binary</strong> — MZ/PE payload from C2<br><br>
      <strong>Base64 telemetry</strong> — encoded host recon data<br><br>
      <strong>POST to raw IP</strong> — no domain resolution
    </div>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-title">Supported Formats</div>
    <div class="format-list">
      <span class="format-tag">PCAP</span>
      <span class="format-tag">PCAPNG</span>
    </div>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-title">IOC Source</div>
    <div class="sidebar-text">GTIG / Google — March 2026<br>UNC1069 / BlueNoroff<br>Educational use only</div>
  </div>
</div>
<div class="main">
  <div class="upload-zone" id="dropZone"
    onclick="document.getElementById('pcap').click()"
    ondragover="event.preventDefault();this.classList.add('dragover')"
    ondragleave="this.classList.remove('dragover')"
    ondrop="handleDrop(event)">
    <div class="upload-title">Drop any PCAP file here to analyze</div>
    <div class="upload-subtitle">Network capture file — analysis starts automatically on upload</div>
    <button class="upload-btn" type="button">Upload File</button>
    <input class="file-input" type="file" id="pcap" accept=".pcap,.pcapng" onchange="fileSelected(this.files[0])">
    <div class="upload-formats">PCAP &nbsp;·&nbsp; PCAPNG</div>
    <div class="file-info" id="fileInfo"></div>
  </div>
  <div class="spinner" id="spinner"><div class="spin"></div><br>Analyzing...</div>
  <div class="result-card" id="resultCard" style="display:none;flex-direction:column">
    <div class="result-module-header">
      <div class="result-module-name" id="resultFilename"></div>
      <span class="severity-badge" id="sevBadge"></span>
    </div>
    <div class="result-pre-wrap">
      <pre id="resultOutput"></pre>
    </div>
  </div>
</div>
</div>
<script>
let currentFile=null,lastReport="",lastFilename="";
function fileSelected(f){if(!f)return;currentFile=f;document.getElementById("fileInfo").style.display="block";document.getElementById("fileInfo").textContent=f.name+" — "+(f.size/1024).toFixed(1)+" KB";document.getElementById("refreshBtn").disabled=false;analyze();}
function handleDrop(e){e.preventDefault();document.getElementById("dropZone").classList.remove("dragover");const f=e.dataTransfer.files[0];if(f)fileSelected(f);}
function resetTool(){currentFile=null;document.getElementById("fileInfo").style.display="none";document.getElementById("fileInfo").textContent="";document.getElementById("refreshBtn").disabled=true;document.getElementById("exportBtn").disabled=true;document.getElementById("resultCard").style.display="none";document.getElementById("pcap").value="";lastReport="";}
async function analyze(){if(!currentFile)return;document.getElementById("resultCard").style.display="none";document.getElementById("spinner").style.display="block";const fd=new FormData();fd.append("pcap",currentFile);try{const res=await fetch("/analyze",{method:"POST",body:fd});const data=await res.json();document.getElementById("spinner").style.display="none";lastReport=data.output;lastFilename=currentFile.name;document.getElementById("resultFilename").textContent=currentFile.name;const b=document.getElementById("sevBadge");b.textContent=data.severity;b.className="severity-badge "+data.severity.toLowerCase();document.getElementById("resultOutput").innerHTML=data.html;document.getElementById("resultCard").style.display="flex";document.getElementById("exportBtn").disabled=false;}catch(e){document.getElementById("spinner").style.display="none";alert("Analysis failed: "+e.message);}}
function exportReport(){if(!lastReport)return;const b=new Blob([lastReport],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=lastFilename.replace(".pcap","").replace(".pcapng","")+"_triage_report.txt";a.click();}
</script>
</body>
</html>'''

@app.route('/')
def index():
    return PAGE

@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('pcap')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
        file.save(tmp.name)
        try:
            result = subprocess.run(['python3', '/app/waveshaper_triage.py', tmp.name], capture_output=True, text=True)
            output = strip_ansi(result.stdout or result.stderr)
        finally:
            os.unlink(tmp.name)
    severity = 'CRITICAL' if 'CRITICAL' in output else 'HIGH' if 'HIGH' in output else 'MEDIUM' if 'MEDIUM' in output else 'LOW'
    html = colorize(output)
    return jsonify({'output': output, 'html': html, 'severity': severity})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
