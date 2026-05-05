// =====================
// Categories (fixed) + Colors
// =====================

const CATEGORIES = {
  ENRICHMENT:  { label: "IOC / Enrichment",        prefix: "↑→", color: "#3B82F6" },
  FRAMEWORKS:  { label: "Frameworks / Knowledge",  prefix: "→→", color: "#8B5CF6" },
  UTILITIES:   { label: "Decode / Utilities",      prefix: "↓↓", color: "#F59E0B" },
  SANDBOX:     { label: "Malware / Sandbox",       prefix: "↓←", color: "#EF4444" },
  RECON:       { label: "Recon / Exposure",        prefix: "↑↑", color: "#F97316" },
  DIRECTORIES: { label: "Directories",             prefix: "→↓", color: "#14B8A6" }
};

// =====================
// Tools
// =====================
const TOOLS = [
  { name:"VirusTotal", url:"https://www.virustotal.com/gui/home/upload", category:"ENRICHMENT", code:"↑→↓↓←",
    desc:"Reputation & analysis for files, hashes, URLs, domains, and IPs." },
  { name:"urlscan.io", url:"https://urlscan.io/", category:"ENRICHMENT", code:"↑→→↓←",
    desc:"Safely scan a URL to capture requests, screenshots, and indicators." },
  { name:"AbuseIPDB", url:"https://www.abuseipdb.com/", category:"ENRICHMENT", code:"↑→←↓←",
    desc:"IP reputation from community abuse reports and confidence scoring." },
  { name:"Cisco Talos Intelligence", url:"https://www.talosintelligence.com/", category:"ENRICHMENT", code:"↑→↓→←",
    desc:"Threat intel for IP/domain reputation and related insights." },

  { name:"MITRE ATT&CK", url:"https://attack.mitre.org/", category:"FRAMEWORKS", code:"→→↑↓←",
    desc:"Tactics & techniques knowledge base for mapping adversary behavior." },
  { name:"ATT&CK Navigator", url:"https://mitre-attack.github.io/attack-navigator/", category:"FRAMEWORKS", code:"→→↓↑←",
    desc:"Visualize and annotate ATT&CK matrices with layers." },

  { name:"CyberChef", url:"https://gchq.github.io/CyberChef/", category:"UTILITIES", code:"↓↓→↑←",
    desc:"Decode/encode/transform data with a huge set of operations." },

  { name:"MalwareBazaar (abuse.ch)", url:"https://bazaar.abuse.ch/", category:"SANDBOX", code:"↓←↓→↑",
    desc:"Malware sample exchange for hunting, alerts, and enrichment." },
  { name:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/", category:"SANDBOX", code:"↓←→↓↑",
    desc:"Automated malware analysis service (Falcon Sandbox powered)." },
  { name:"ANY.RUN", url:"https://any.run/", category:"SANDBOX", code:"↓←↑→→",
    desc:"Interactive malware sandbox with live analysis and reports." },
  { name:"Joe Sandbox", url:"https://www.joesandbox.com/", category:"SANDBOX", code:"↓←↑↓→",
    desc:"Automated malware and phishing analysis with deep reporting." },

  { name:"Shodan", url:"https://www.shodan.io/", category:"RECON", code:"↑↑→↓←",
    desc:"Search engine for internet-connected devices and exposures." },
  { name:"Censys", url:"https://censys.io/", category:"RECON", code:"↑↑→→←",
    desc:"Internet asset discovery and certificate/host intelligence." },
  { name:"crt.sh", url:"https://crt.sh/", category:"RECON", code:"↑↑↓→←",
    desc:"Certificate Transparency search to find certs and related domains." },
  { name:"SecurityTrails", url:"https://securitytrails.com/", category:"RECON", code:"↑↑↓↓→",
    desc:"Historical DNS and domain infrastructure intelligence." },

  { name:"OSINT Framework", url:"https://osintframework.com/", category:"DIRECTORIES", code:"→↓↑→↑",
    desc:"Curated OSINT directory organized by investigation type." },
  { name:"cipher387 OSINT tool collection (GitHub)", url:"https://github.com/cipher387/osint_stuff_tool_collection", category:"DIRECTORIES", code:"→↓→↑↓",
    desc:"Large OSINT tools collection repo (hundreds+)." }
];

const TOOL_BY_CODE = new Map(TOOLS.map(t => [t.code, t]));

// =====================
// State
// =====================
let sequence = [];
const MAX_LEN = 9;

const LS_HISTORY = "strat_history_v1";
const LS_AUDIO = "strat_audio_v1";

const BUFFER_TIMEOUT_MS = 3500;
let bufferTimer = null;

let trainingMode = false;
let trainingTarget = null;
let trainingFails = 0;

// Mission prompts by category (keeps it “SOC real”)
const TRAINING_MISSIONS = {
  ENRICHMENT:  "MISSION: Enrich an indicator (hash / URL / domain / IP).",
  FRAMEWORKS:  "MISSION: Map observed behavior to tactics and techniques.",
  UTILITIES:   "MISSION: Decode/transform data (URL/B64/timestamps/etc.).",
  SANDBOX:     "MISSION: Analyze a suspicious file/URL in a sandbox.",
  RECON:       "MISSION: Investigate external exposure & infrastructure.",
  DIRECTORIES: "MISSION: Find the right OSINT resource directory fast."
};

// =====================
// DOM
// =====================
const sequenceDisplay = document.getElementById("sequenceDisplay");
const statusText = document.getElementById("statusText");
const prefixHint = document.getElementById("prefixHint");
const resultRegion = document.getElementById("resultRegion");

const btnClear = document.getElementById("btnClear");
const btnUndo = document.getElementById("btnUndo");
const btnLaunch = document.getElementById("btnLaunch");

const toolSearch = document.getElementById("toolSearch");
const toolList = document.getElementById("toolList");
const historyList = document.getElementById("historyList");
const btnClearHistory = document.getElementById("btnClearHistory");

const consoleBody = document.getElementById("consoleBody");
const trainingPrompt = document.getElementById("trainingPrompt");

const btnHelp = document.getElementById("btnHelp");
const helpModal = document.getElementById("helpModal");
const helpBackdrop = document.getElementById("helpBackdrop");
const btnCloseHelp = document.getElementById("btnCloseHelp");
const categoryLegend = document.getElementById("categoryLegend");

const btnTraining = document.getElementById("btnTraining");

const audioToggle = document.getElementById("audioToggle");

// =====================
// Helpers
// =====================
function setStatus(msg, tone="neutral"){
  statusText.textContent = msg;
  const toneColor = tone === "ok" ? "var(--teal)" : tone === "bad" ? "var(--red)" : "var(--muted)";
  statusText.style.color = toneColor;
}

function getSequenceString(){ return sequence.join(""); }

function renderPrefixHint(s){
  if (s.length < 2) { prefixHint.textContent = "Type a code…"; return; }
  const prefix = s.slice(0,2);
  const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
  prefixHint.textContent = cat ? `Category: ${cat.label} (${cat.prefix})` : "Unknown prefix";
}

function renderSequence(){
  const s = getSequenceString();
  if (!s.length){
    sequenceDisplay.textContent = "—";
    renderPrefixHint(s);
    return;
  }

  sequenceDisplay.innerHTML = "";
  s.split("").forEach((ch, idx) => {
    const span = document.createElement("span");
    span.className = "arrow" + (idx === s.length - 1 ? " last" : "");
    span.textContent = ch;
    sequenceDisplay.appendChild(span);
  });

  renderPrefixHint(s);
}

function flashConsole(kind="flash"){
  consoleBody.classList.remove("flash","success","timeout");
  void consoleBody.offsetWidth;
  consoleBody.classList.add(kind);
}

function resetBufferTimer(){
  clearTimeout(bufferTimer);
  consoleBody.classList.remove("timeout");

  bufferTimer = setTimeout(() => {
    if (sequence.length){
      sequence = [];
      renderSequence();
      renderResult(null);
      consoleBody.classList.add("timeout");
      setStatus("Stratagem buffer timed out.", "neutral");
      // trainingPrompt remains visible if trainingMode is on
    }
  }, BUFFER_TIMEOUT_MS);
}

function clearSequence(){
  sequence = [];
  renderSequence();
  renderResult(null);
  setStatus(trainingMode ? "Training active. Enter the correct stratagem." : "Ready.", "neutral");
}

function undoSequence(){
  sequence.pop();
  renderSequence();
  renderResult(null);
  setStatus(trainingMode ? "Training active. Enter the correct stratagem." : "Ready.", "neutral");
}

function safeOpen(url){
  window.open(url, "_blank", "noopener,noreferrer");
}

// =====================
// Audio (WebAudio synth, optional)
// =====================
let audioEnabled = false;
let audioCtx = null;

function loadAudioPref(){
  try{ audioEnabled = JSON.parse(localStorage.getItem(LS_AUDIO) || "false"); }
  catch{ audioEnabled = false; }
  audioToggle.checked = audioEnabled;
}

function saveAudioPref(val){
  audioEnabled = !!val;
  localStorage.setItem(LS_AUDIO, JSON.stringify(audioEnabled));
}

function ensureAudio(){
  if (!audioEnabled) return null;
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  if (audioCtx.state === "suspended") audioCtx.resume();
  return audioCtx;
}

function playTone({freq=440, duration=0.06, type="sine", gain=0.04, when=0}){
  const ctx = ensureAudio();
  if (!ctx) return;

  const t0 = ctx.currentTime + when;
  const osc = ctx.createOscillator();
  const g = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, t0);

  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + 0.01);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + duration);

  osc.connect(g);
  g.connect(ctx.destination);
  osc.start(t0);
  osc.stop(t0 + duration + 0.02);
}

function sfxTick(){ playTone({freq:980, duration:0.035, type:"square", gain:0.015}); }
function sfxSuccess(){
  playTone({freq:523.25, duration:0.07, type:"sine", gain:0.035, when:0.00});
  playTone({freq:659.25, duration:0.07, type:"sine", gain:0.035, when:0.07});
  playTone({freq:783.99, duration:0.09, type:"sine", gain:0.04,  when:0.14});
}
function sfxLaunch(){ playTone({freq:880, duration:0.09, type:"triangle", gain:0.03}); }

// =====================
// Rendering
// =====================
function renderResult(tool, animateDrop=false){
  resultRegion.innerHTML = "";
  if (!tool) return;

  const cat = CATEGORIES[tool.category];
  const accent = cat?.color || "#94a3b8";

  const card = document.createElement("div");
  card.className = "result-card" + (animateDrop ? " drop" : "");
  card.innerHTML = `
    <div class="accent" style="background:${accent}"></div>
    <div class="rc-body">
      <div class="rc-top">
        <div>
          <h3 class="rc-title">${tool.name}</h3>
          <div class="rc-meta">
            <span class="badge" style="border-color:${accent}55;">
              <span style="color:${accent};font-weight:800;">●</span>
              ${cat.label} • ${cat.prefix} • Code:
              <span style="letter-spacing:4px;">${tool.code.split("").join(" ")}</span>
            </span>
          </div>
        </div>
        <button class="btn primary" id="resultLaunch" type="button">Open</button>
      </div>
      <p class="rc-desc">${tool.desc}</p>
      <div class="rc-actions">
        <span class="badge">Tip: Press Enter to launch</span>
        <span class="badge">Backspace = Undo • Esc = Clear</span>
      </div>
    </div>
  `;

  resultRegion.appendChild(card);
  document.getElementById("resultLaunch").addEventListener("click", () => {
    addHistory(tool);
    sfxLaunch();
    safeOpen(tool.url);
    setStatus(`Launched: ${tool.name}`, "ok");
  });
}

// =====================
// Help + Legend (FIXED)
// =====================
function openHelp(){
  // Populate legend every time help opens (so it never goes stale)
  categoryLegend.innerHTML = "";
  Object.values(CATEGORIES).forEach(c => {
    const item = document.createElement("div");
    item.className = "legend-item";
    item.innerHTML = `
      <div class="legend-swatch" style="background:${c.color}"></div>
      <div>
        <div class="lbl">${c.label}</div>
        <div class="sub">Prefix: <span style="letter-spacing:4px;">${c.prefix.split("").join(" ")}</span></div>
      </div>
    `;
    categoryLegend.appendChild(item);
  });

  helpModal.hidden = false;
}
function closeHelp(){ helpModal.hidden = true; }

// =====================
// Training Mode (HOME BUTTON)
// =====================
function startTraining(){
  trainingMode = true;
  trainingFails = 0;
  trainingTarget = TOOLS[Math.floor(Math.random() * TOOLS.length)];

  trainingPrompt.hidden = false;
  trainingPrompt.textContent = TRAINING_MISSIONS[trainingTarget.category] || `MISSION: ${trainingTarget.desc}`;

  btnTraining.textContent = "Training: ON";
  setStatus("Training active. Enter the correct stratagem.", "neutral");

  // Clear buffer + hide result; you must earn the card
  sequence = [];
  renderSequence();
  renderResult(null);
}

function stopTraining(){
  trainingMode = false;
  trainingTarget = null;
  trainingFails = 0;

  trainingPrompt.hidden = true;
  trainingPrompt.textContent = "";

  btnTraining.textContent = "Training";
  setStatus("Ready.", "neutral");

  // Clear buffer
  sequence = [];
  renderSequence();
  renderResult(null);
}

function nextTrainingMission(){
  trainingFails = 0;
  trainingTarget = TOOLS[Math.floor(Math.random() * TOOLS.length)];
  trainingPrompt.textContent = TRAINING_MISSIONS[trainingTarget.category] || `MISSION: ${trainingTarget.desc}`;
  sequence = [];
  renderSequence();
  renderResult(null);
  setStatus("New mission. Enter the correct stratagem.", "neutral");
}

function handleTrainingAttempt(code){
  if (!trainingTarget) return;

  if (code === trainingTarget.code){
    flashConsole("success");
    sfxSuccess();
    setStatus("✅ Mission success.", "ok");
    renderResult(trainingTarget, true);

    // Load next mission shortly after success
    setTimeout(() => nextTrainingMission(), 700);
    return;
  }

  trainingFails++;
  setStatus("❌ Incorrect stratagem.", "bad");

  if (trainingFails >= 2){
    const prefix = trainingTarget.code.slice(0,2);
    const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
    setStatus(`Hint: Prefix ${prefix} (${cat?.label || "category"}).`, "neutral");
  }
}

// =====================
// Matching (normal vs training)
// =====================
function tryMatchAndRender(){
  const code = getSequenceString();
  if (!code) return;

  if (trainingMode){
    // Only evaluate attempts when typed length matches any known code length
    const anySameLength = [...TOOL_BY_CODE.keys()].some(k => k.length === code.length);
    if (anySameLength) handleTrainingAttempt(code);
    return;
  }

  const tool = TOOL_BY_CODE.get(code);
  if (tool){
    renderResult(tool, true);
    flashConsole("success");
    sfxSuccess();
    setStatus(`Matched: ${tool.name}`, "ok");
  }
}

function launchCurrent(){
  const code = getSequenceString();
  if (!code.length){
    setStatus("Enter a code first.", "neutral");
    return;
  }

  if (trainingMode){
    handleTrainingAttempt(code);
    return;
  }

  const tool = TOOL_BY_CODE.get(code);
  if (tool){
    addHistory(tool);
    sfxLaunch();
    safeOpen(tool.url);
    setStatus(`Launched: ${tool.name}`, "ok");
  } else {
    setStatus("No match for that code.", "bad");
  }
}

// =====================
// History + Browser
// =====================
function loadHistory(){
  try{
    const raw = localStorage.getItem(LS_HISTORY);
    return raw ? JSON.parse(raw) : [];
  }catch{
    return [];
  }
}
function saveHistory(items){
  localStorage.setItem(LS_HISTORY, JSON.stringify(items.slice(0, 20)));
}
function addHistory(tool){
  const items = loadHistory();
  const entry = { name: tool.name, code: tool.code, when: new Date().toLocaleString(), category: tool.category };
  const next = [entry, ...items].filter((v, i, a) => i === a.findIndex(x => x.name === v.name && x.code === v.code));
  saveHistory(next);
  renderHistory();
}
function renderHistory(){
  const items = loadHistory();
  historyList.innerHTML = items.length ? "" : `<div class="tiny">No recent calls yet.</div>`;
  for (const h of items){
    const cat = CATEGORIES[h.category];
    const color = cat?.color || "#94a3b8";
    const row = document.createElement("div");
    row.className = "hitem";
    row.innerHTML = `
      <div class="line1">
        <div class="t"><span style="color:${color};">●</span> ${h.name}</div>
        <div class="ts">${h.when}</div>
      </div>
      <div class="c">${h.code.split("").join(" ")}</div>
    `;
    historyList.appendChild(row);
  }
}

function renderToolList(filter=""){
  const q = (filter || "").toLowerCase().trim();
  const filtered = !q ? TOOLS : TOOLS.filter(t => {
    const cat = CATEGORIES[t.category]?.label || "";
    return t.name.toLowerCase().includes(q) ||
           (t.desc || "").toLowerCase().includes(q) ||
           cat.toLowerCase().includes(q) ||
           t.code.includes(q);
  });

  toolList.innerHTML = filtered.length ? "" : `<div class="tiny">No matches.</div>`;

  for (const t of filtered){
    const cat = CATEGORIES[t.category];
    const color = cat?.color || "#94a3b8";
    const row = document.createElement("div");
    row.className = "toolrow";
    row.innerHTML = `
      <div class="toolchip" style="background:${color}"></div>
      <div style="min-width:0;">
        <p class="toolname">${t.name}</p>
        <div class="toolmeta">${cat.label} • Prefix ${cat.prefix}</div>
        <div class="toolcode">${t.code.split("").join(" ")}</div>
      </div>
      <div class="toola">
        <button class="btn ghost small" type="button">Open</button>
      </div>
    `;
    row.querySelector("button").addEventListener("click", () => {
      addHistory(t);
      sfxLaunch();
      safeOpen(t.url);
      setStatus(`Launched: ${t.name}`, "ok");
    });
    toolList.appendChild(row);
  }
}

// =====================
// Input handling
// =====================
function onKeyDown(e){
  const k = e.key;

  if (k === "Escape"){ e.preventDefault(); clearSequence(); return; }
  if (k === "Backspace"){ e.preventDefault(); undoSequence(); return; }
  if (k === "Enter"){ e.preventDefault(); launchCurrent(); return; }

  const map = { ArrowUp:"↑", ArrowDown:"↓", ArrowLeft:"←", ArrowRight:"→" };
  if (map[k]){
    e.preventDefault();
    if (sequence.length >= MAX_LEN){
      setStatus("Max code length reached. Press Esc to clear.", "bad");
      return;
    }
    sequence.push(map[k]);
    renderSequence();
    flashConsole("flash");
    sfxTick();
    resetBufferTimer();
    tryMatchAndRender();
  }
}

// =====================
// Wire up UI
// =====================
btnClear.addEventListener("click", clearSequence);
btnUndo.addEventListener("click", undoSequence);
btnLaunch.addEventListener("click", launchCurrent);

toolSearch.addEventListener("input", (e) => renderToolList(e.target.value));

btnClearHistory.addEventListener("click", () => {
  localStorage.removeItem(LS_HISTORY);
  renderHistory();
  setStatus("History cleared.", "neutral");
});

btnHelp.addEventListener("click", openHelp);
btnCloseHelp.addEventListener("click", closeHelp);
helpBackdrop.addEventListener("click", closeHelp);

btnTraining.addEventListener("click", () => {
  if (!trainingMode) startTraining();
  else stopTraining();
});

audioToggle.addEventListener("change", (e) => {
  saveAudioPref(e.target.checked);
  setStatus(audioEnabled ? "Audio enabled." : "Audio disabled.", "neutral");
  ensureAudio();
});

// =====================
// Init
// =====================
document.addEventListener("keydown", onKeyDown);
loadAudioPref();
renderSequence();
renderToolList("");
renderHistory();
setStatus("Ready.", "neutral");
