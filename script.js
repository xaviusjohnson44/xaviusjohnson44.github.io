// =====================
// Fixed Categories + Colors (Left accent bar)
// =====================
const CATEGORIES = {
  ENRICHMENT: { label: "IOC / Enrichment", prefix: "↑→", color: "#3B82F6" },
  FRAMEWORKS: { label: "Frameworks / Knowledge", prefix: "→→", color: "#8B5CF6" },
  UTILITIES:  { label: "Decode / Utilities", prefix: "↓↓", color: "#F59E0B" },
  SANDBOX:    { label: "Malware / Sandbox", prefix: "↓←", color: "#EF4444" },
  RECON:      { label: "Recon / Exposure", prefix: "↑↑", color: "#F97316" },
  DIRECTORIES:{ label: "Directories", prefix: "→↓", color: "#14B8A6" }
};

// =====================
// Tool Registry (edit here to add/remove tools)
// codes are arrow glyph strings with NO spaces, e.g. "↑→↓↓←"
// =====================
const TOOLS = [
  // ENRICHMENT (↑→...)
  {
    name: "VirusTotal",
    url: "https://www.virustotal.com/gui/home/upload",
    category: "ENRICHMENT",
    code: "↑→↓↓←",
    desc: "Reputation & analysis for files, hashes, URLs, domains, and IPs."
  },
  {
    name: "urlscan.io",
    url: "https://urlscan.io/",
    category: "ENRICHMENT",
    code: "↑→→↓←",
    desc: "Safely scan a URL to capture requests, screenshots, and indicators."
  },
  {
    name: "AbuseIPDB",
    url: "https://www.abuseipdb.com/",
    category: "ENRICHMENT",
    code: "↑→←↓←",
    desc: "IP reputation from community abuse reports and confidence scoring."
  },
  {
    name: "Cisco Talos Intelligence",
    url: "https://www.talosintelligence.com/",
    category: "ENRICHMENT",
    code: "↑→↓→←",
    desc: "Threat intel for IP/domain reputation and related insights."
  },

  // FRAMEWORKS (→→...)
  {
    name: "MITRE ATT&CK",
    url: "https://attack.mitre.org/",
    category: "FRAMEWORKS",
    code: "→→↑↓←",
    desc: "Tactics & techniques knowledge base for mapping adversary behavior."
  },
  {
    name: "ATT&CK Navigator",
    url: "https://mitre-attack.github.io/attack-navigator/",
    category: "FRAMEWORKS",
    code: "→→↓↑←",
    desc: "Visualize and annotate ATT&CK matrices with layers."
  },

  // UTILITIES (↓↓...)
  {
    name: "CyberChef",
    url: "https://gchq.github.io/CyberChef/",
    category: "UTILITIES",
    code: "↓↓→↑←",
    desc: "Decode/encode/transform data with a huge set of operations."
  },

  // SANDBOX (↓←...)
  {
    name: "MalwareBazaar (abuse.ch)",
    url: "https://bazaar.abuse.ch/",
    category: "SANDBOX",
    code: "↓←↓→↑",
    desc: "Malware sample exchange for hunting, alerts, and enrichment."
  },
  {
    name: "Hybrid Analysis",
    url: "https://www.hybrid-analysis.com/",
    category: "SANDBOX",
    code: "↓←→↓↑",
    desc: "Automated malware analysis service (Falcon Sandbox powered)."
  },
  {
    name: "ANY.RUN",
    url: "https://any.run/",
    category: "SANDBOX",
    code: "↓←↑→→",
    desc: "Interactive malware sandbox with live analysis and reports."
  },
  {
    name: "Joe Sandbox",
    url: "https://www.joesandbox.com/",
    category: "SANDBOX",
    code: "↓←↑↓→",
    desc: "Automated malware and phishing analysis with deep reporting."
  },

  // RECON (↑↑...)
  {
    name: "Shodan",
    url: "https://www.shodan.io/",
    category: "RECON",
    code: "↑↑→↓←",
    desc: "Search engine for internet-connected devices and exposures."
  },
  {
    name: "Censys",
    url: "https://censys.io/",
    category: "RECON",
    code: "↑↑→→←",
    desc: "Internet asset discovery and certificate/host intelligence."
  },
  {
    name: "crt.sh",
    url: "https://crt.sh/",
    category: "RECON",
    code: "↑↑↓→←",
    desc: "Certificate Transparency search to find certs and related domains."
  },
  {
    name: "SecurityTrails",
    url: "https://securitytrails.com/",
    category: "RECON",
    code: "↑↑↓↓→",
    desc: "Historical DNS and domain infrastructure intelligence."
  },

  // DIRECTORIES (→↓...)
  {
    name: "OSINT Framework",
    url: "https://osintframework.com/",
    category: "DIRECTORIES",
    code: "→↓↑→↑",
    desc: "Curated OSINT directory organized by investigation type."
  },
  {
    name: "cipher387 OSINT tool collection (GitHub)",
    url: "https://github.com/cipher387/osint_stuff_tool_collection",
    category: "DIRECTORIES",
    code: "→↓→↑↓",
    desc: "Large OSINT tools collection repo (hundreds+)."
  }
];

// Build a fast lookup map
const TOOL_BY_CODE = new Map(TOOLS.map(t => [t.code, t]));

// =====================
// State
// =====================
let sequence = [];
const MAX_LEN = 9; // keep roomy; most codes are 4-6

// LocalStorage keys
const LS_HISTORY = "strat_history_v1";
const LS_AUDIO = "strat_audio_v1";

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

const helpModal = document.getElementById("helpModal");
const btnHelp = document.getElementById("btnHelp");
const btnCloseHelp = document.getElementById("btnCloseHelp");
const helpBackdrop = document.getElementById("helpBackdrop");
const categoryLegend = document.getElementById("categoryLegend");

const consoleBody = document.getElementById("consoleBody");
const audioToggle = document.getElementById("audioToggle");

// =====================
// Helpers
// =====================
function nowStamp(){
  const d = new Date();
  return d.toLocaleString([], { year:"numeric", month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit" });
}

function setStatus(msg, tone="neutral"){
  statusText.textContent = msg;
  const toneColor = tone === "ok" ? "var(--teal)" : tone === "bad" ? "var(--red)" : "var(--muted)";
  statusText.style.color = toneColor;
}

function getSequenceString(){
  return sequence.join("");
}

function renderPrefixHint(s){
  if (s.length < 2) {
    prefixHint.textContent = "Type a code…";
    return;
  }
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

  // Build spans so the last arrow can animate
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
  if (!consoleBody) return;
  consoleBody.classList.remove("flash", "success");
  // force reflow so the animation retriggers
  void consoleBody.offsetWidth;
  consoleBody.classList.add(kind);
}

function clearSequence(){
  sequence = [];
  renderSequence();
  renderResult(null);
  setStatus("Ready.", "neutral");
}

function undoSequence(){
  sequence.pop();
  renderSequence();
  renderResult(null);
  setStatus("Ready.", "neutral");
}

function normalize(str){
  return (str || "").toLowerCase().trim();
}

function safeOpen(url){
  window.open(url, "_blank", "noopener,noreferrer");
}

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
            <span class="badge" style="border-color: ${accent}55;">
              <span style="color:${accent}; font-weight:800;">●</span>
              ${cat?.label || "Category"} • ${cat?.prefix || ""} • Code: <span style="letter-spacing:4px;">${tool.code.split("").join(" ")}</span>
            </span>
          </div>
        </div>
        <button class="btn primary" type="button" id="resultLaunch">Open</button>
      </div>
      <p class="rc-desc">${tool.desc || ""}</p>
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

function suggestByPrefix(prefix){
  return TOOLS.filter(t => t.code.startsWith(prefix)).slice(0,6);
}

function tryMatchAndRender(){
  const s = getSequenceString();
  if (!s.length) return null;

  const tool = TOOL_BY_CODE.get(s);
  if (tool){
    renderResult(tool, true); // drop animation on match
    setStatus(`Matched: ${tool.name}`, "ok");

    flashConsole("success");
    sfxSuccess();

    return tool;
  }

  // If the prefix matches a category, show a helpful hint
  if (s.length >= 2){
    const prefix = s.slice(0,2);
    const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
    if (cat){
      const suggestions = suggestByPrefix(prefix);
      if (suggestions.length){
        setStatus(`No exact match yet. ${cat.label} prefix detected (${prefix}).`, "neutral");
      } else {
        setStatus(`Prefix recognized (${prefix}) but no tools assigned yet.`, "neutral");
      }
      renderResult(null);
      return null;
    }
  }

  setStatus("Unknown code/prefix.", "bad");
  renderResult(null);
  return null;
}

// =====================
// Audio (optional) - WebAudio synth stingers
// =====================
let audioEnabled = false;
let audioCtx = null;

function loadAudioPref(){
  try{
    const raw = localStorage.getItem(LS_AUDIO);
    audioEnabled = raw ? JSON.parse(raw) : false;
  }catch{
    audioEnabled = false;
  }
  if (audioToggle) audioToggle.checked = audioEnabled;
}

function saveAudioPref(val){
  audioEnabled = !!val;
  localStorage.setItem(LS_AUDIO, JSON.stringify(audioEnabled));
}

function ensureAudio(){
  if (!audioEnabled) return null;
  if (!audioCtx){
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
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

function sfxTick(){
  // very subtle click
  playTone({freq: 980, duration: 0.035, type:"square", gain: 0.015});
}

function sfxSuccess(){
  // short “call-in” stinger: three rising tones
  playTone({freq: 523.25, duration: 0.07, type:"sine", gain: 0.035, when: 0.00}); // C5
  playTone({freq: 659.25, duration: 0.07, type:"sine", gain: 0.035, when: 0.07}); // E5
  playTone({freq: 783.99, duration: 0.09, type:"sine", gain: 0.04,  when: 0.14}); // G5
}

function sfxLaunch(){
  playTone({freq: 880, duration: 0.09, type:"triangle", gain: 0.03});
}

// =====================
// History
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
  const entry = { name: tool.name, code: tool.code, when: nowStamp(), category: tool.category };
  const next = [entry, ...items].filter((v, i, a) =>
    i === a.findIndex(x => x.name === v.name && x.code === v.code)
  );
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

// =====================
// Tool Browser
// =====================
function renderToolList(filter=""){
  const q = normalize(filter);
  const filtered = !q ? TOOLS : TOOLS.filter(t => {
    const cat = CATEGORIES[t.category]?.label || "";
    return normalize(t.name).includes(q) ||
           normalize(t.desc).includes(q) ||
           normalize(cat).includes(q) ||
           normalize(t.code).includes(q);
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
        <div class="toolmeta">${cat?.label || ""} • Prefix ${cat?.prefix || ""}</div>
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
// Help Modal
// =====================
function openHelp(){
  categoryLegend.innerHTML = "";
  Object.entries(CATEGORIES).forEach(([key, c]) => {
    const el = document.createElement("div");
    el.className = "legend-item";
    el.innerHTML = `
      <div class="legend-swatch" style="background:${c.color}"></div>
      <div>
        <div class="lbl">${c.label}</div>
        <div class="sub">Prefix: <span style="letter-spacing:4px;">${c.prefix.split("").join(" ")}</span></div>
      </div>
    `;
    categoryLegend.appendChild(el);
  });

  helpModal.hidden = false;
}

function closeHelp(){
  helpModal.hidden = true;
}

// =====================
// Input handling (Arrow keys only)
// =====================
function onKeyDown(e){
  const k = e.key;

  if (k === "Escape"){
    e.preventDefault();
    clearSequence();
    return;
  }
  if (k === "Backspace"){
    e.preventDefault();
    undoSequence();
    return;
  }
  if (k === "Enter"){
    e.preventDefault();
    launchCurrent();
    return;
  }

  const map = {
    ArrowUp: "↑",
    ArrowDown: "↓",
    ArrowLeft: "←",
    ArrowRight: "→"
  };

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

    tryMatchAndRender();
  }
}

function launchCurrent(){
  const s = getSequenceString();
  if (!s.length){
    setStatus("Enter a code first.", "neutral");
    return;
  }

  const tool = TOOL_BY_CODE.get(s);
  if (tool){
    addHistory(tool);
    sfxLaunch();
    safeOpen(tool.url);
    setStatus(`Launched: ${tool.name}`, "ok");
    return;
  }

  // helpful suggestions if prefix matches
  if (s.length >= 2){
    const prefix = s.slice(0,2);
    const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
    if (cat){
      const sug = suggestByPrefix(prefix);
      const names = sug.map(x => x.name).join(", ");
      setStatus(sug.length
        ? `No exact match. Try one of: ${names}`
        : `Prefix recognized (${prefix}) but no tools assigned yet.`,
        "bad"
      );
      return;
    }
  }

  setStatus("No match for that code.", "bad");
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

if (audioToggle){
  audioToggle.addEventListener("change", (e) => {
    saveAudioPref(e.target.checked);
    setStatus(audioEnabled ? "Audio enabled." : "Audio disabled.", "neutral");
    ensureAudio(); // attempt to unlock audio context on toggle
  });
}

// Init
document.addEventListener("keydown", onKeyDown);
renderSequence();
renderToolList("");
renderHistory();
loadAudioPref();
setStatus("Ready.", "neutral");


// =====================
// Training Mode State
// =====================
let trainingMode = false;
let trainingTarget = null;
let trainingFails = 0;

// =====================
// Buffer Timeout
// =====================
const BUFFER_TIMEOUT_MS = 3500;
let bufferTimer = null;

function resetBufferTimer(){
  clearTimeout(bufferTimer);
  consoleBody.classList.remove("timeout");

  bufferTimer = setTimeout(() => {
    if(sequence.length){
      sequence = [];
      renderSequence();
      consoleBody.classList.add("timeout");
      setStatus("Stratagem buffer timed out.", "neutral");
    }
  }, BUFFER_TIMEOUT_MS);
}

// =====================
// Training Helpers
// =====================
function startTraining(){
  trainingMode = true;
  trainingFails = 0;
  trainingTarget = TOOLS[Math.floor(Math.random()*TOOLS.length)];
  document.getElementById("trainingPrompt").hidden = false;
  document.getElementById("trainingPrompt").textContent =
    `MISSION: ${trainingTarget.desc}`;
  setStatus("Training mode active.", "neutral");
}

function stopTraining(){
  trainingMode = false;
  trainingTarget = null;
  document.getElementById("trainingPrompt").hidden = true;
  setStatus("Training mode off.", "neutral");
}

// =====================
// Match logic override
// =====================
function tryMatchAndRender(){
  const s = getSequenceString();
  if(!s) return;

  if(trainingMode){
    if(trainingTarget.code === s){
      renderResult(trainingTarget,true);
      sfxSuccess();
      setStatus("✅ Mission success.", "ok");
      startTraining(); // next mission
    }else{
      trainingFails++;
      setStatus("❌ Incorrect stratagem.", "bad");
      if(trainingFails>=2){
        setStatus(`Hint: Prefix ${trainingTarget.code.slice(0,2)}`, "neutral");
      }
    }
    return;
  }

  const tool = TOOL_BY_CODE.get(s);
  if(tool){
    renderResult(tool,true);
    sfxSuccess();
    setStatus(`Matched: ${tool.name}`, "ok");
  }
}

// =====================
// Input handling
// =====================
function onKeyDown(e){
  const map={ArrowUp:"↑",ArrowDown:"↓",ArrowLeft:"←",ArrowRight:"→"};

  if(map[e.key]){
    e.preventDefault();
    sequence.push(map[e.key]);
    renderSequence();
    sfxTick();
    resetBufferTimer();
    tryMatchAndRender();
  }

  if(e.key==="Escape"){clearSequence()}
  if(e.key==="Backspace"){undoSequence()}
  if(e.key==="Enter"){launchCurrent()}
}

// =====================
// Help modal wiring
// =====================
document.getElementById("trainingToggle")
  .addEventListener("change",e=>{
    e.target.checked ? startTraining() : stopTraining();
  });

// =====================
// Init
// =====================
document.addEventListener("keydown",onKeyDown);
loadAudioPref();
renderSequence();
renderToolList();
renderHistory();
setStatus("Ready.", "neutral");
