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
// Tool Registry
// =====================
const TOOLS = [
  { name:"VirusTotal", url:"https://www.virustotal.com/gui/home/upload", category:"ENRICHMENT", code:"↑→↓↓←",
    desc:"Enrich: file/hash/URL/domain/IP reputation & analysis." },
  { name:"urlscan.io", url:"https://urlscan.io/", category:"ENRICHMENT", code:"↑→→↓←",
    desc:"Enrich: safe URL scan with screenshot, requests, and indicators." },
  { name:"AbuseIPDB", url:"https://www.abuseipdb.com/", category:"ENRICHMENT", code:"↑→←↓←",
    desc:"Enrich: IP reputation from abuse reports." },
  { name:"Cisco Talos Intelligence", url:"https://www.talosintelligence.com/", category:"ENRICHMENT", code:"↑→↓→←",
    desc:"Enrich: threat intel for IP/domain reputation." },

  { name:"MITRE ATT&CK", url:"https://attack.mitre.org/", category:"FRAMEWORKS", code:"→→↑↓←",
    desc:"Map: tactics & techniques knowledge base." },
  { name:"ATT&CK Navigator", url:"https://mitre-attack.github.io/attack-navigator/", category:"FRAMEWORKS", code:"→→↓↑←",
    desc:"Visualize: build ATT&CK layers and coverage maps." },

  { name:"CyberChef", url:"https://gchq.github.io/CyberChef/", category:"UTILITIES", code:"↓↓→↑←",
    desc:"Decode/transform: Swiss Army knife for data." },

  { name:"MalwareBazaar", url:"https://bazaar.abuse.ch/", category:"SANDBOX", code:"↓←↓→↑",
    desc:"Malware: sample exchange + hunting." },
  { name:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/", category:"SANDBOX", code:"↓←→↓↑",
    desc:"Malware: automated sandbox reports." },
  { name:"ANY.RUN", url:"https://any.run/", category:"SANDBOX", code:"↓←↑→→",
    desc:"Malware: interactive sandbox." },
  { name:"Joe Sandbox", url:"https://www.joesandbox.com/", category:"SANDBOX", code:"↓←↑↓→",
    desc:"Malware/phishing: deep analysis reports." },

  { name:"Shodan", url:"https://www.shodan.io/", category:"RECON", code:"↑↑→↓←",
    desc:"Recon: internet-connected device search." },
  { name:"Censys", url:"https://censys.io/", category:"RECON", code:"↑↑→→←",
    desc:"Recon: internet asset discovery & cert intel." },
  { name:"crt.sh", url:"https://crt.sh/", category:"RECON", code:"↑↑↓→←",
    desc:"Recon: certificate transparency search." },
  { name:"SecurityTrails", url:"https://securitytrails.com/", category:"RECON", code:"↑↑↓↓→",
    desc:"Recon: historical DNS & infra intel." },

  { name:"OSINT Framework", url:"https://osintframework.com/", category:"DIRECTORIES", code:"→↓↑→↑",
    desc:"Directory: curated OSINT resources by type." },
  { name:"cipher387 OSINT collection", url:"https://github.com/cipher387/osint_stuff_tool_collection", category:"DIRECTORIES", code:"→↓→↑↓",
    desc:"Directory: huge OSINT tool collection." }
];

const TOOL_BY_CODE = new Map(TOOLS.map(t => [t.code, t]));

// =====================
// State
// =====================
let sequence = [];
const MAX_LEN = 9;

const LS_HISTORY = "strat_history_v1";
const LS_AUDIO   = "strat_audio_v1";

// Buffer timeout (Helldivers feel)
const BUFFER_TIMEOUT_MS = 3500;
let bufferTimer = null;

// Training mode
let trainingMode = false;
let trainingTarget = null;
let trainingFails = 0;

// =====================
// DOM
// =====================
const sequenceDisplay = document.getElementById("sequenceDisplay");
const statusText = document.getElementById("statusText");
const prefixHint = document.getElementById("prefixHint");
const resultRegion = document.getElementById("resultRegion");
const consoleBody = document.getElementById("consoleBody");

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

const trainingToggle = document.getElementById("trainingToggle");
const trainingPrompt = document.getElementById("trainingPrompt");

const audioToggle = document.getElementById("audioToggle");

// =====================
// Helpers
// =====================
function setStatus(msg, tone="neutral"){
  if (!statusText) return;
  statusText.textContent = msg;
  const toneColor = tone === "ok" ? "var(--teal)" : tone === "bad" ? "var(--red)" : "var(--muted)";
  statusText.style.color = toneColor;
}

function getSequenceString(){ return sequence.join(""); }

function renderPrefixHint(s){
  if (!prefixHint) return;
  if (s.length < 2) { prefixHint.textContent = "Type a code…"; return; }
  const prefix = s.slice(0,2);
  const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
  prefixHint.textContent = cat ? `Category: ${cat.label} (${cat.prefix})` : "Unknown prefix";
}

function renderSequence(){
  const s = getSequenceString();
  if (!sequenceDisplay) return;

  if (!s.length){
    sequenceDisplay.textContent = "—";
    renderPrefixHint(s);
    return;
  }

  // spans for last-arrow animation (CSS)
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
  consoleBody.classList.remove("flash", "success", "timeout");
  void consoleBody.offsetWidth;
  consoleBody.classList.add(kind);
}

function resetBufferTimer(){
  clearTimeout(bufferTimer);
  if (consoleBody) consoleBody.classList.remove("timeout");

  bufferTimer = setTimeout(() => {
    if (sequence.length){
      sequence = [];
      renderSequence();
      if (consoleBody) consoleBody.classList.add("timeout");
      setStatus("Stratagem buffer timed out.", "neutral");
      // In training mode, keep the prompt; only clear buffer
    }
  }, BUFFER_TIMEOUT_MS);
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

function safeOpen(url){
  window.open(url, "_blank", "noopener,noreferrer");
}

// =====================
// Audio (optional) - WebAudio
// =====================
let audioEnabled = false;
let audioCtx = null;

function loadAudioPref(){
  try { audioEnabled = JSON.parse(localStorage.getItem(LS_AUDIO) || "false"); }
  catch { audioEnabled = false; }
  if (audioToggle) audioToggle.checked = audioEnabled;
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

function sfxTick(){ playTone({freq: 980, duration: 0.035, type:"square", gain: 0.015}); }
function sfxSuccess(){
  playTone({freq: 523.25, duration: 0.07, type:"sine", gain: 0.035, when: 0.00});
  playTone({freq: 659.25, duration: 0.07, type:"sine", gain: 0.035, when: 0.07});
  playTone({freq: 783.99, duration: 0.09, type:"sine", gain: 0.04,  when: 0.14});
}
function sfxLaunch(){ playTone({freq: 880, duration: 0.09, type:"triangle", gain: 0.03}); }

// =====================
// Result rendering (with drop animation)
// =====================
function renderResult(tool, animateDrop=false){
  if (!resultRegion) return;
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
              ${cat?.label || "Category"} • ${cat?.prefix || ""} • Code:
              <span style="letter-spacing:4px;">${tool.code.split("").join(" ")}</span>
            </span>
          </div>
        </div>
        <button class="btn primary" id="resultLaunch" type="button">Open</button>
      </div>
      <p class="rc-desc">${tool.desc || ""}</p>
      <div class="rc-actions">
        <span class="badge">Tip: Press Enter to launch</span>
        <span class="badge">Backspace = Undo • Esc = Clear</span>
      </div>
    </div>
  `;

  resultRegion.appendChild(card);
  document.getElementById("resultLaunch")?.addEventListener("click", () => {
    addHistory(tool);
    sfxLaunch();
    safeOpen(tool.url);
    setStatus(`Launched: ${tool.name}`, "ok");
  });
}

// =====================
// Training Mode
// =====================
const TRAINING_MISSIONS = [
  { key:"ENRICHMENT",  prompt:"MISSION: Enrich a suspicious indicator (hash / URL / domain / IP)." },
  { key:"FRAMEWORKS",  prompt:"MISSION: Map adversary behavior to tactics/techniques." },
  { key:"UTILITIES",   prompt:"MISSION: Decode/transform data (urls, b64, timestamps, etc.)." },
  { key:"SANDBOX",     prompt:"MISSION: Analyze a suspicious file or malware behavior safely." },
  { key:"RECON",       prompt:"MISSION: Discover internet exposure / external infrastructure clues." },
  { key:"DIRECTORIES", prompt:"MISSION: Find the right OSINT resource directory quickly." }
];

function startTraining(){
  trainingMode = true;
  trainingFails = 0;

  // choose a tool, bias toward variety
  trainingTarget = TOOLS[Math.floor(Math.random() * TOOLS.length)];
  const catKey = trainingTarget.category;

  const mission = TRAINING_MISSIONS.find(m => m.key === catKey);
  if (trainingPrompt){
    trainingPrompt.hidden = false;
    trainingPrompt.textContent = mission ? mission.prompt : `MISSION: ${trainingTarget.desc}`;
  }

  // don’t show the tool card immediately in training; earn it
  renderResult(null);
  setStatus("Training mode active. Enter the correct stratagem.", "neutral");
}

function stopTraining(){
  trainingMode = false;
  trainingTarget = null;
  trainingFails = 0;
  if (trainingPrompt){
    trainingPrompt.hidden = true;
    trainingPrompt.textContent = "";
  }
  setStatus("Training mode off.", "neutral");
}

function handleTrainingAttempt(code){
  if (!trainingTarget) return;

  if (code === trainingTarget.code){
    // success
    flashConsole("success");
    sfxSuccess();
    setStatus("✅ Mission success. New mission loaded.", "ok");
    renderResult(trainingTarget, true);

    // next mission after a brief moment
    setTimeout(() => {
      clearSequence();
      startTraining();
    }, 500);
    return;
  }

  // fail
  trainingFails++;
  setStatus("❌ Incorrect stratagem.", "bad");

  // give a hint after 2 fails
  if (trainingFails >= 2){
    const prefix = trainingTarget.code.slice(0,2);
    const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
    setStatus(`Hint: Use prefix ${prefix} (${cat?.label || "category"}).`, "neutral");
  }
}

// =====================
// Normal matching
// =====================
function tryMatchAndRender(){
  const code = getSequenceString();
  if (!code) return null;

  if (trainingMode){
    // Only validate on full match length or Enter? We'll allow immediate check on exact-match attempt:
    // If user is still typing, don't penalize unless the code exactly matches a tool length.
    // But simplest: check only when they match any tool code length.
    if ([...TOOL_BY_CODE.keys()].some(k => k.length === code.length)) {
      handleTrainingAttempt(code);
    }
    return null;
  }

  const tool = TOOL_BY_CODE.get(code);
  if (tool){
    renderResult(tool, true);
    flashConsole("success");
    sfxSuccess();
    setStatus(`Matched: ${tool.name}`, "ok");
    return tool;
  }

  // prefix hint
  if (code.length >= 2){
    const prefix = code.slice(0,2);
    const cat = Object.values(CATEGORIES).find(c => c.prefix === prefix);
    if (cat){
      setStatus(`No exact match yet. ${cat.label} prefix detected (${prefix}).`, "neutral");
      renderResult(null);
      return null;
    }
  }

  setStatus("Unknown code/prefix.", "bad");
  renderResult(null);
  return null;
}

function launchCurrent(){
  const code = getSequenceString();
  if (!code.length){
    setStatus("Enter a code first.", "neutral");
    return;
  }

  // In training mode, Enter should validate attempt
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
// History + Browser Lists
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
  if (!historyList) return;
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
  if (!toolList) return;
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
// Help Modal wiring (safe even if elements missing)
// =====================
function openHelp(){ if (helpModal) helpModal.hidden = false; }
function closeHelp(){ if (helpModal) helpModal.hidden = true; }

btnHelp?.addEventListener("click", openHelp);
btnCloseHelp?.addEventListener("click", closeHelp);

// Click outside modal to close (if backdrop exists)
helpModal?.querySelector(".modal-backdrop")?.addEventListener("click", closeHelp);

// Training toggle wiring (THIS is usually what’s missing)
trainingToggle?.addEventListener("change", (e) => {
  if (e.target.checked) startTraining();
  else stopTraining();
});

// Audio toggle
audioToggle?.addEventListener("change", (e) => {
  saveAudioPref(e.target.checked);
  setStatus(audioEnabled ? "Audio enabled." : "Audio disabled.", "neutral");
  ensureAudio();
});

// Buttons
btnClear?.addEventListener("click", clearSequence);
btnUndo?.addEventListener("click", undoSequence);
btnLaunch?.addEventListener("click", launchCurrent);

btnClearHistory?.addEventListener("click", () => {
  localStorage.removeItem(LS_HISTORY);
  renderHistory();
  setStatus("History cleared.", "neutral");
});

toolSearch?.addEventListener("input", (e) => renderToolList(e.target.value));

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
// Init
// =====================
document.addEventListener("keydown", onKeyDown);
loadAudioPref();
renderSequence();
renderToolList("");
renderHistory();
setStatus("Ready.", "neutral");
