// Interactive JavaScript for IoMT Hospital Clinical Security Operations Center (CSOC)

const PRESETS = {
  port_scan: {
    device_name: "Baxter Sigma Smart Infusion Pump (Bed 04)",
    ward_name: "ICU Ward Room 101",
    Header_Length: 54.0,
    Protocol_Type: 6.0,
    Duration: 0.01,
    Rate: 850.5,
    Srate: 850.5,
    syn_flag_number: 1.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 0.0,
    Max: 60.0,
    Min: 60.0,
    Tot_size: 60.0,
    Variance: 0.0,
    Magnitue: 10.95,
    IAT: 0.001,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.10.15",
    flow_id: "FLW-ICU-0842",
    device_idx: 1,
  },
  os_scan: {
    device_name: "Hamilton-C6 ICU Mechanical Ventilator",
    ward_name: "Trauma ICU Bay 2",
    Header_Length: 60.0,
    Protocol_Type: 6.0,
    Duration: 0.05,
    Rate: 320.0,
    Srate: 320.0,
    syn_flag_number: 1.0,
    fin_count: 1.0,
    rst_count: 1.0,
    psh_flag_number: 1.0,
    ack_flag_number: 0.0,
    Max: 120.0,
    Min: 40.0,
    Tot_size: 120.0,
    Variance: 12.5,
    Magnitue: 15.2,
    IAT: 0.005,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.10.20",
    flow_id: "FLW-VENT-0319",
    device_idx: 2,
  },
  benign: {
    device_name: "Philips IntelliVue MX800 Patient Monitor",
    ward_name: "Coronary Care Unit (CCU) Bed 01",
    Header_Length: 20.0,
    Protocol_Type: 6.0,
    Duration: 0.85,
    Rate: 12.4,
    Srate: 12.4,
    syn_flag_number: 0.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 1.0,
    Max: 1420.0,
    Min: 64.0,
    Tot_size: 1420.0,
    Variance: 245.5,
    Magnitue: 28.5,
    IAT: 0.08,
    is_critical_asset: true,
    source_ip: "192.168.10.25",
    destination_ip: "192.168.10.200", // Central Nursing Telemetry Server
    flow_id: "FLW-VITALS-9901",
    device_idx: 3,
  },
  vul_scan: {
    device_name: "GE Centricity PACS Imaging Server",
    ward_name: "Hospital Data Center / Radiology",
    Header_Length: 128.0,
    Protocol_Type: 6.0,
    Duration: 0.15,
    Rate: 150.0,
    Srate: 150.0,
    syn_flag_number: 0.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 1.0,
    ack_flag_number: 1.0,
    Max: 1500.0,
    Min: 128.0,
    Tot_size: 1500.0,
    Variance: 85.0,
    Magnitue: 35.8,
    IAT: 0.02,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.20.50",
    flow_id: "FLW-PACS-4421",
    device_idx: 4,
  },
  port_scan_mri: {
    device_name: "Siemens SOMATOM CT / MRI Scanner",
    ward_name: "Radiology Imaging Suite 1",
    Header_Length: 54.0,
    Protocol_Type: 6.0,
    Duration: 0.015,
    Rate: 720.0,
    Srate: 720.0,
    syn_flag_number: 1.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 0.0,
    Max: 60.0,
    Min: 60.0,
    Tot_size: 60.0,
    Variance: 0.0,
    Magnitue: 10.95,
    IAT: 0.0012,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.20.12",
    flow_id: "FLW-MRI-1102",
    device_idx: 5,
  },
  os_scan_anes: {
    device_name: "Draeger Perseus Anesthesia Workstation",
    ward_name: "Operating Theatre 3 (OT-3)",
    Header_Length: 60.0,
    Protocol_Type: 6.0,
    Duration: 0.04,
    Rate: 280.0,
    Srate: 280.0,
    syn_flag_number: 1.0,
    fin_count: 1.0,
    rst_count: 1.0,
    psh_flag_number: 1.0,
    ack_flag_number: 0.0,
    Max: 120.0,
    Min: 40.0,
    Tot_size: 120.0,
    Variance: 12.5,
    Magnitue: 15.2,
    IAT: 0.006,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.30.18",
    flow_id: "FLW-ANES-7714",
    device_idx: 6,
  },
  port_scan_defib: {
    device_name: "Medtronic Lifepak Defibrillator & ECG",
    ward_name: "Operating Theatre 1 (OT-1)",
    Header_Length: 54.0,
    Protocol_Type: 6.0,
    Duration: 0.012,
    Rate: 680.0,
    Srate: 680.0,
    syn_flag_number: 1.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 0.0,
    Max: 60.0,
    Min: 60.0,
    Tot_size: 60.0,
    Variance: 0.0,
    Magnitue: 10.95,
    IAT: 0.0015,
    is_critical_asset: true,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.30.22",
    flow_id: "FLW-DEFIB-0081",
    device_idx: 7,
  },
  ping_sweep: {
    device_name: "Wireless Wearable ECG Telemetry Subnet",
    ward_name: "General Ward Room 302",
    Header_Length: 28.0,
    Protocol_Type: 1.0,
    Duration: 0.001,
    Rate: 1200.0,
    Srate: 1200.0,
    syn_flag_number: 0.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 0.0,
    Max: 84.0,
    Min: 84.0,
    Tot_size: 84.0,
    Variance: 0.0,
    Magnitue: 12.96,
    IAT: 0.0008,
    is_critical_asset: false,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.40.255",
    flow_id: "FLW-SWEEP-0912",
    device_idx: 8,
  },
  benign_bed: {
    device_name: "Stryker InTouch Connected Smart Bed",
    ward_name: "Post-Op Ward Room 208",
    Header_Length: 20.0,
    Protocol_Type: 6.0,
    Duration: 0.5,
    Rate: 8.5,
    Srate: 8.5,
    syn_flag_number: 0.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 1.0,
    Max: 500.0,
    Min: 64.0,
    Tot_size: 500.0,
    Variance: 110.0,
    Magnitue: 22.0,
    IAT: 0.12,
    is_critical_asset: false,
    source_ip: "192.168.40.110",
    destination_ip: "192.168.40.200",
    flow_id: "FLW-BED-5120",
    device_idx: 9,
  },
  host_discovery: {
    device_name: "Stryker Smart Bed Hub (Bed 08)",
    ward_name: "Post-Op Ward Room 208",
    Header_Length: 32.0,
    Protocol_Type: 6.0,
    Duration: 0.02,
    Rate: 520.0,
    Srate: 520.0,
    syn_flag_number: 1.0,
    fin_count: 0.0,
    rst_count: 0.0,
    psh_flag_number: 0.0,
    ack_flag_number: 0.0,
    Max: 70.0,
    Min: 54.0,
    Tot_size: 70.0,
    Variance: 4.5,
    Magnitue: 11.2,
    IAT: 0.002,
    is_critical_asset: false,
    source_ip: "192.168.1.105",
    destination_ip: "192.168.50.110",
    flow_id: "FLW-HOST-5081",
    device_idx: 8,
  },
};

let currentPresetKey = "port_scan";

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initVlanNetworkSimulator();
  initNurseStation();
  loadHealth();
  loadAlerts();

  document.getElementById("btn-refresh")?.addEventListener("click", () => {
    loadHealth();
    loadAlerts();
  });

  document.getElementById("btn-refresh-alerts")?.addEventListener("click", loadAlerts);
});

// Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetId = tab.getAttribute("data-tab");
      switchTab(targetId);
    });
  });
}

function switchTab(targetId) {
  document.querySelectorAll(".tab-btn").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));

  const targetBtn = document.querySelector(`.tab-btn[data-tab="${targetId}"]`);
  targetBtn?.classList.add("active");
  const targetContent = document.getElementById(targetId);
  targetContent?.classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Patient Clinical Ecosystem for all 5 Hospital Users
const USER_PATIENTS = {
  10: {
    userId: 1,
    vlanId: 10,
    patientName: "Robert Chen",
    location: "ICU Ward — Bed 04",
    patientAge: "64 yrs | Male",
    mrn: "PT-ICU-2026-084",
    diagnosis: "Acute Coronary Syndrome & Post-CABG Recovery",
    deviceName: "Baxter Sigma Smart Infusion Pump (Bed 04)",
    deviceIp: "192.168.10.15",
    portProtocol: "HL7 / TCP 80",
    attackType: "Port Scan (SYN Reconnaissance)",
    presetKey: "port_scan",
    advisoryText: "An unauthorized computer from outside the ward tried to scan the digital communication ports on the <strong>Baxter Infusion Pump</strong> connected to patient Robert Chen. Our hospital's AI security shield intercepted this scan in <strong>0.96 milliseconds</strong>. <strong>The drug delivery system is shielded, and the prescribed Norepinephrine rate (2.50 mcg/min) is running safely without any change!</strong>",
    step1Title: "Check Patient Vital Signs",
    step1VitalsHtml: `
      <span>Heart Rate: <strong>74 bpm (Normal)</strong></span>
      <span>Blood Pressure: <strong>122/81 mmHg (Stable)</strong></span>
      <span>Oxygen (SpO2): <strong>98% (Normal)</strong></span>
    `,
    step1Footer: "✅ Patient Robert Chen is hemodynamically stable. No clinical distress.",
    step2Title: "Verify Physical Infusion Pump",
    step2DetailsHtml: `
      <span>Medication: <strong>Norepinephrine</strong></span>
      <span>Current Rate: <strong>2.50 mcg/min</strong></span>
      <span>Dosage Status: <strong style="color:#10b981;">SAFE (Prescribed Rate)</strong></span>
    `,
    step2Footer: "✅ Pump screen confirms rate matches physician order. No dosage alteration.",
    step3Title: "Clinical Action & IT Coordination",
    step3DetailsHtml: `
      <span>IT Security: <strong style="color:#10b981;">Automatically Notified</strong></span>
      <span>Physical Pump: <strong>DO NOT DISCONNECT</strong></span>
      <span>Telemetry: <strong>Monitoring Continuously</strong></span>
    `,
    step3Footer: "✅ AI defense shielded the device. Keep infusion running as prescribed."
  },
  20: {
    userId: 2,
    vlanId: 20,
    patientName: "Sarah Jenkins",
    location: "Trauma ICU — Bed 02",
    patientAge: "52 yrs | Female",
    mrn: "PT-TRAUMA-2026-019",
    diagnosis: "Severe Acute Respiratory Distress (Post-Thoracic Surgery)",
    deviceName: "Hamilton-C6 Mechanical Ventilator (Bed 02)",
    deviceIp: "192.168.20.20",
    portProtocol: "Modbus 502 / TCP",
    attackType: "OS Fingerprinting Scan",
    presetKey: "os_scan",
    advisoryText: "A rogue computer attempted an OS fingerprinting reconnaissance scan against Bed 02 Mechanical Ventilator to map internal firmware services. The IDS intercepted and flagged the probe in <strong>0.96 milliseconds</strong>. <strong>Continuous respiratory ventilation and oxygen supply to Sarah Jenkins remain 100% active and uncompromised!</strong>",
    step1Title: "Check Patient Respiratory Vitals",
    step1VitalsHtml: `
      <span>Oxygen (SpO2): <strong>99% (Stable)</strong></span>
      <span>Tidal Volume: <strong>480 mL (Normal: 475-500)</strong></span>
      <span>Resp Rate: <strong>14 breaths/min (SIMV)</strong></span>
    `,
    step1Footer: "✅ Patient Sarah Jenkins has optimal arterial oxygenation. No respiratory distress.",
    step2Title: "Verify Mechanical Ventilator State",
    step2DetailsHtml: `
      <span>Ventilator Mode: <strong>SIMV + Pressure Support</strong></span>
      <span>FiO2 Delivery: <strong>40% (Prescribed Baseline)</strong></span>
      <span>Airway Pressure: <strong style="color:#10b981;">18 cmH2O (Normal & Safe)</strong></span>
    `,
    step2Footer: "✅ Ventilator telemetry confirms continuous, uninterrupted lung ventilation.",
    step3Title: "Clinical Action & Ventilator Protocol",
    step3DetailsHtml: `
      <span>IT Security: <strong style="color:#10b981;">Dispatched to CSOC</strong></span>
      <span>Ventilator Circuit: <strong>DO NOT POWER DOWN</strong></span>
      <span>Bedside Monitor: <strong>Telemetry Stream Online</strong></span>
    `,
    step3Footer: "✅ Firmware shielded by IDS. Maintain current mechanical ventilation."
  },
  30: {
    userId: 3,
    vlanId: 30,
    patientName: "David Miller",
    location: "Cath Lab — Bed 01",
    patientAge: "71 yrs | Male",
    mrn: "PT-RAD-2026-302",
    diagnosis: "Coronary Angiogram & Cardiac Catheterization",
    deviceName: "GE Centricity PACS Server (Cath Lab)",
    deviceIp: "192.168.30.50",
    portProtocol: "DICOM 104 / TCP",
    attackType: "Vulnerability Probe Scan",
    presetKey: "vul_scan",
    advisoryText: "Network vulnerability probing scan intercepted targeting Cath Lab PACS image acquisition server. Real-time IDS alerted in <strong>0.96 milliseconds</strong>. High-definition diagnostic fluoroscopy images and live coronary catheterization video feed streaming without frame loss.",
    step1Title: "Check Patient Cath Lab Vitals",
    step1VitalsHtml: `
      <span>Heart Rate: <strong>78 bpm (Controlled)</strong></span>
      <span>Blood Pressure: <strong>130/84 mmHg</strong></span>
      <span>Patient State: <strong>Conscious & Comfortable</strong></span>
    `,
    step1Footer: "✅ Patient David Miller is stable during post-catheterization observation.",
    step2Title: "Verify Imaging Server Feed",
    step2DetailsHtml: `
      <span>PACS DICOM Link: <strong>Secure (TLS Encrypted)</strong></span>
      <span>Cine Angiogram: <strong>Zero Frame Latency</strong></span>
      <span>Diagnostic Archive: <strong style="color:#10b981;">Integrity Verified 100%</strong></span>
    `,
    step2Footer: "✅ Medical imaging workstation uncompromised. Cath lab procedurals unaffected.",
    step3Title: "Clinical Action & Radiology Protocol",
    step3DetailsHtml: `
      <span>IT Security: <strong style="color:#10b981;">SOC Incident Flagged</strong></span>
      <span>PACS Connection: <strong>MAINTAIN ACTIVE FEED</strong></span>
      <span>Patient Care: <strong>Proceed as Scheduled</strong></span>
    `,
    step3Footer: "✅ Probe neutralized at reconnaissance stage before medical data could be accessed."
  },
  40: {
    userId: 4,
    vlanId: 40,
    patientName: "Maria Rodriguez",
    location: "CCU Ward — Bed 03",
    patientAge: "58 yrs | Female",
    mrn: "PT-CCU-2026-115",
    diagnosis: "Non-ST Elevation Myocardial Infarction (NSTEMI)",
    deviceName: "Philips Vital Telemetry Monitor (Bed 03)",
    deviceIp: "192.168.40.25",
    portProtocol: "HL7 / DICOM / UDP",
    attackType: "Ping Sweep (ICMP Reconnaissance)",
    presetKey: "ping_sweep",
    advisoryText: "Subnet ICMP ping sweep reconnaissance detected seeking active bedside monitors in CCU. IDS flagged the scan in <strong>0.96 milliseconds</strong>. The Philips bedside monitor continues broadcasting continuous 12-lead ECG rhythms to the central nursing station with zero packet drop.",
    step1Title: "Check Patient Cardiac Telemetry",
    step1VitalsHtml: `
      <span>Heart Rate: <strong>72 bpm (Normal Sinus)</strong></span>
      <span>Blood Pressure: <strong>118/75 mmHg</strong></span>
      <span>ST-Segment: <strong>Isoelectric (No Ischemia)</strong></span>
    `,
    step1Footer: "✅ Patient Maria Rodriguez exhibits stable sinus rhythm without arrhythmia.",
    step2Title: "Verify Telemetry Broadcast",
    step2DetailsHtml: `
      <span>ECG Lead Status: <strong>All 5 Leads Connected</strong></span>
      <span>Nurse Desk Stream: <strong>Real-Time Telemetry Live</strong></span>
      <span>Packet Loss: <strong style="color:#10b981;">0.0% (Zero Drop)</strong></span>
    `,
    step2Footer: "✅ Bedside telemetry transmitter unaffected. Central nursing desk in sync.",
    step3Title: "Clinical Action & Monitoring Protocol",
    step3DetailsHtml: `
      <span>IT Security: <strong style="color:#10b981;">Auto-Alerted Central SOC</strong></span>
      <span>Telemetry Unit: <strong>DO NOT POWER DOWN</strong></span>
      <span>Cardiac Monitor: <strong>Continuous Observation</strong></span>
    `,
    step3Footer: "✅ Reconnaissance sweep intercepted. Clinical monitoring is fully protected."
  },
  50: {
    userId: 5,
    vlanId: 50,
    patientName: "Arthur Pendelton",
    location: "Post-Op Ward — Bed 08",
    patientAge: "68 yrs | Male",
    mrn: "PT-POSTOP-2026-052",
    diagnosis: "Total Hip Arthroplasty (Post-Surgical Day 1)",
    deviceName: "Stryker Smart Bed Hub (Bed 08)",
    deviceIp: "192.168.50.110",
    portProtocol: "MQTT / CoAP / TCP 1883",
    attackType: "Host Discovery Probe",
    presetKey: "host_discovery",
    advisoryText: "Unauthorized host discovery probe detected scanning smart bed IoT gateway in Room 208. Intercepted within <strong>0.96 milliseconds</strong>. Patient exit-detection alarm, position sensors, and pressure ulcer prevention telemetry are working normally without disruption.",
    step1Title: "Check Post-Op Patient Vitals",
    step1VitalsHtml: `
      <span>Heart Rate: <strong>68 bpm (Resting)</strong></span>
      <span>Blood Pressure: <strong>120/78 mmHg</strong></span>
      <span>Pain Score: <strong>2/10 (Controlled)</strong></span>
    `,
    step1Footer: "✅ Patient Arthur Pendelton is resting comfortably in Bed 08 post-surgery.",
    step2Title: "Verify Smart Bed Sensor Status",
    step2DetailsHtml: `
      <span>Bed Exit Alarm: <strong>ACTIVE & ARMED</strong></span>
      <span>Angle Position: <strong>30° Head-of-Bed Up</strong></span>
      <span>Fall Prevention: <strong style="color:#10b981;">Guardrails Engaged</strong></span>
    `,
    step2Footer: "✅ Bedside safety sensors online. Fall risk prevention system functioning properly.",
    step3Title: "Clinical Action & Ward Protocol",
    step3DetailsHtml: `
      <span>IT Security: <strong style="color:#10b981;">Incident Logged in CSOC</strong></span>
      <span>Smart Bed Hub: <strong>KEEP POWER ON</strong></span>
      <span>Nurse Call Bell: <strong>Verified & Working</strong></span>
    `,
    step3Footer: "✅ Probe blocked before any lateral movement. Patient recovery safe."
  }
};

// Dedicated Nurse Ward Clinical Alert Station Logic (Simple, Jargon-Free for Nurses)
function initNurseStation() {
  // Nurse station event handlers (if any additional controls needed)
}

async function triggerNurseAttackMode(presetKey = "port_scan", vlanId = 10) {
  const user = USER_PATIENTS[vlanId] || USER_PATIENTS[10];
  const preset = PRESETS[presetKey] || PRESETS.port_scan;

  // Play crisp 3-pulse clinical alert alarm audio
  playAlertBeep();

  // 1. Update Nurse Alert Screen Box UI to Emergency Alert
  const box = document.getElementById("nurse-alert-box");
  if (box) {
    box.className = "nurse-alert-screen-box alert-active";
  }

  const siren = document.getElementById("nurse-siren-icon");
  if (siren) siren.textContent = "🚨";

  const chip = document.getElementById("nurse-chip-status");
  if (chip) {
    chip.textContent = "EMERGENCY CLINICAL CYBER ALERT";
    chip.className = "nurse-chip-critical";
  }

  // 2. Specific Patient Name and Bed Number
  const pName = document.getElementById("nurse-patient-name");
  if (pName) pName.textContent = user.patientName;

  const pLoc = document.getElementById("nurse-patient-loc");
  if (pLoc) pLoc.textContent = user.location;

  const headline = document.getElementById("nurse-headline-text");
  if (headline) headline.textContent = `Unauthorized ${user.attackType} on ${user.deviceName}`;

  const safety = document.getElementById("nurse-patient-safety");
  if (safety) {
    safety.textContent = "PATIENT SAFE & STABLE";
    safety.className = "patient-safety-badge safe";
  }

  // 3. Specific Plain-Language Explanation for THIS Patient & Device
  const expTitle = document.getElementById("nurse-exp-title");
  if (expTitle) expTitle.textContent = `What Happened — Patient: ${user.patientName} (${user.location}):`;

  const plainDesc = document.getElementById("nurse-plain-desc");
  if (plainDesc) {
    plainDesc.innerHTML = user.advisoryText;
  }

  // 4. Specific 3-Step Protocol for THIS Patient
  const step1Title = document.getElementById("nurse-step1-title");
  if (step1Title) step1Title.textContent = user.step1Title;
  const step1Vitals = document.getElementById("nurse-step1-vitals");
  if (step1Vitals) step1Vitals.innerHTML = user.step1VitalsHtml;
  const step1Footer = document.getElementById("nurse-step1-footer");
  if (step1Footer) step1Footer.textContent = user.step1Footer;

  const step2Title = document.getElementById("nurse-step2-title");
  if (step2Title) step2Title.textContent = user.step2Title;
  const step2Details = document.getElementById("nurse-step2-details");
  if (step2Details) step2Details.innerHTML = user.step2DetailsHtml;
  const step2Footer = document.getElementById("nurse-step2-footer");
  if (step2Footer) step2Footer.textContent = user.step2Footer;

  const step3Title = document.getElementById("nurse-step3-title");
  if (step3Title) step3Title.textContent = user.step3Title;
  const step3Details = document.getElementById("nurse-step3-details");
  if (step3Details) step3Details.innerHTML = user.step3DetailsHtml;
  const step3Footer = document.getElementById("nurse-step3-footer");
  if (step3Footer) step3Footer.textContent = user.step3Footer;

  // 5. Unique Incident Alert ID
  const alertId = document.getElementById("nurse-alert-id");
  const randAlt = `ALT-VLAN${vlanId}-${Math.floor(1000 + Math.random() * 9000)}`;
  if (alertId) alertId.textContent = randAlt;

  // Send to /predict to register alert in CSOC audit log
  try {
    const payload = {
      ...preset,
      flow_id: `FLW-NURSE-U${user.userId}-${Date.now().toString().slice(-4)}`,
    };
    await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    loadAlerts();
  } catch (e) {
    console.error("Predict error", e);
  }
}

// Preset Buttons in Simulation Console
function initPresets() {
  document.querySelectorAll(".btn-preset").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll(".btn-preset").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      const pKey = btn.getAttribute("data-preset");
      applyPreset(pKey);
    });
  });
}

// 5-VLAN Integrated Hospital Network Alert Simulator
function initVlanNetworkSimulator() {
  document.querySelectorAll(".btn-vlan-attack").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      const vlanId = parseInt(btn.getAttribute("data-vlan"), 10);
      const presetKey = btn.getAttribute("data-preset");
      const preset = PRESETS[presetKey];
      if (!preset) return;

      // 1. Highlight targeted VLAN card
      document.querySelectorAll(".vlan-box").forEach(box => box.classList.remove("attack-active"));
      const targetBox = document.getElementById(`vlan-box-${vlanId}`);
      if (targetBox) targetBox.classList.add("attack-active");

      // 2. Launch specific user's clinical alert and route to Nurse Ward Station
      await triggerNurseAttackMode(presetKey, vlanId);
      switchTab("tab-nurse");
    });
  });
}

function playAlertBeep() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === "suspended") {
      ctx.resume();
    }

    // Urgent 3-tone hospital telemetry alarm (880Hz, 880Hz, 1100Hz)
    const tones = [
      { time: 0.0, freq: 880, dur: 0.14 },
      { time: 0.18, freq: 880, dur: 0.14 },
      { time: 0.36, freq: 1100, dur: 0.22 },
    ];

    tones.forEach((t) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(t.freq, ctx.currentTime + t.time);
      gain.gain.setValueAtTime(0.35, ctx.currentTime + t.time);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + t.time + t.dur);
      osc.start(ctx.currentTime + t.time);
      osc.stop(ctx.currentTime + t.time + t.dur);
    });
  } catch (e) {
    console.warn("Audio alert beep failed:", e);
  }
}

function applyPreset(pKey) {
  const data = PRESETS[pKey];
  if (!data) return;
  currentPresetKey = pKey;

  // Set Hospital Medical Asset Metadata
  const devNameInput = document.getElementById("inp-device-name");
  if (devNameInput) devNameInput.value = data.device_name || "Medical IoMT Node";

  const wardInput = document.getElementById("inp-device-ward");
  if (wardInput) wardInput.value = data.ward_name || "General Clinical Ward";

  const flowIdInput = document.getElementById("inp-flow-id");
  if (flowIdInput) flowIdInput.value = data.flow_id || ("FLW-" + Date.now().toString().slice(-6));

  const srcInput = document.getElementById("inp-src-ip");
  if (srcInput) srcInput.value = data.source_ip || "192.168.1.105";

  const dstInput = document.getElementById("inp-dst-ip");
  if (dstInput) dstInput.value = data.destination_ip || "192.168.10.15";

  const critCheckbox = document.getElementById("inp-critical-asset");
  if (critCheckbox) critCheckbox.checked = !!data.is_critical_asset;

  // Fill feature inputs
  for (const [key, val] of Object.entries(data)) {
    const input = document.getElementById(`f-${key}`);
    if (input) input.value = val;
  }
}

// Form Submission for /predict
function initForm() {
  const form = document.getElementById("prediction-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("btn-submit-predict");
    btn.textContent = "Analyzing Clinical Flow...";
    btn.disabled = true;

    try {
      const payload = {
        flow_id: document.getElementById("inp-flow-id").value || "FLW-" + Date.now(),
        source_ip: document.getElementById("inp-src-ip").value,
        destination_ip: document.getElementById("inp-dst-ip").value,
        is_critical_asset: document.getElementById("inp-critical-asset").checked,
        device_name: document.getElementById("inp-device-name").value,
        ward_name: document.getElementById("inp-device-ward").value,
        rst_count: parseFloat(document.getElementById("f-rst_count").value) || 0,
        fin_count: parseFloat(document.getElementById("f-fin_count").value) || 0,
        psh_flag_number: parseFloat(document.getElementById("f-psh_flag_number").value) || 0,
        syn_flag_number: parseFloat(document.getElementById("f-syn_flag_number").value) || 0,
        Header_Length: parseFloat(document.getElementById("f-Header_Length").value) || 0,
        Max: parseFloat(document.getElementById("f-Max").value) || 0,
        "Tot size": parseFloat(document.getElementById("f-Tot_size").value) || 0,
        Min: parseFloat(document.getElementById("f-Min").value) || 0,
        Variance: parseFloat(document.getElementById("f-Variance").value) || 0,
        Magnitue: parseFloat(document.getElementById("f-Magnitue").value) || 0,
        Rate: parseFloat(document.getElementById("f-Rate").value) || 0,
        IAT: parseFloat(document.getElementById("f-IAT").value) || 0,
        ack_flag_number: parseFloat(document.getElementById("f-ack_flag_number").value) || 0,
        Srate: parseFloat(document.getElementById("f-Srate").value) || 0,
        Duration: parseFloat(document.getElementById("f-Duration").value) || 0,
      };

      const res = await fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      displayResult(data, payload);
      loadAlerts();
    } catch (err) {
      alert("Clinical inference request failed: " + err.message);
    } finally {
      btn.textContent = "Run Clinical Flow Classification";
      btn.disabled = false;
    }
  });
}

function displayResult(data, payload) {
  document.getElementById("res-placeholder")?.classList.add("hidden");
  const resData = document.getElementById("res-data");
  resData?.classList.remove("hidden");

  document.getElementById("res-badge-status").textContent = "Diagnosis Completed";
  document.getElementById("res-pred-class").textContent = data.prediction;
  document.getElementById("res-attack-type").textContent = data.attack_type;
  document.getElementById("res-confidence").textContent = (data.confidence * 100).toFixed(1) + "%";
  document.getElementById("res-alert-id").textContent = data.alert_id || "None (Benign Clinical Telemetry)";
  document.getElementById("res-model-ver").textContent = "XGBoost Champion (15 Features)";

  // Device Summary Tag
  const devSummary = document.getElementById("res-device-summary");
  if (devSummary) {
    devSummary.textContent = `${payload.device_name || "IoMT Device"} | ${payload.ward_name || "Ward"} (IP: ${payload.destination_ip})`;
  }

  // Severity Tag
  const sevTag = document.getElementById("res-severity-tag");
  sevTag.textContent = data.severity;
  sevTag.style.borderColor = getSeverityColor(data.severity);
  sevTag.style.color = getSeverityColor(data.severity);

  // Clinical Impact Banner
  const banner = document.getElementById("res-clinical-banner");
  const bannerIcon = document.getElementById("banner-icon");
  const bannerTitle = document.getElementById("banner-title");
  const bannerDesc = document.getElementById("banner-desc");

  if (data.prediction === "Benign") {
    banner.style.borderColor = "rgba(16, 185, 129, 0.4)";
    banner.style.background = "rgba(16, 185, 129, 0.08)";
    bannerIcon.textContent = "🛡️";
    bannerTitle.textContent = "Normal Clinical Telemetry Confirmed";
    bannerTitle.style.color = "#6ee7b7";
    bannerDesc.innerHTML = `Medical data streaming from <strong>${payload.device_name}</strong> to Central Nurse Station conforms to normal baseline. <strong>Zero false alarm:</strong> telemetry link remains 100% uninterrupted.`;
  } else if (payload.is_critical_asset) {
    banner.style.borderColor = "rgba(244, 63, 94, 0.4)";
    banner.style.background = "rgba(244, 63, 94, 0.1)";
    bannerIcon.textContent = "🚨";
    bannerTitle.textContent = "Life-Critical IoMT Asset Threat Escalated";
    bannerTitle.style.color = "#fca5a5";
    bannerDesc.innerHTML = `Target is a <strong>Life-Critical Device (${payload.device_name})</strong> in ${payload.ward_name}. Reconnaissance (${data.prediction}) detected. Risk escalated to <strong>${data.severity}</strong> to safeguard patient safety.`;
  } else {
    banner.style.borderColor = "rgba(245, 158, 11, 0.4)";
    banner.style.background = "rgba(245, 158, 11, 0.08)";
    bannerIcon.textContent = "⚠️";
    bannerTitle.textContent = "Reconnaissance Activity Flagged";
    bannerTitle.style.color = "#fcd34d";
    bannerDesc.innerHTML = `Unusual network reconnaissance (${data.prediction}) detected targeting ${payload.device_name}. Threat dispatched to SDN Controller.`;
  }

  // Render Probabilities
  const pContainer = document.getElementById("prob-bars-container");
  pContainer.innerHTML = "";
  if (data.probabilities) {
    for (const [cls, pVal] of Object.entries(data.probabilities)) {
      const pct = (pVal * 100).toFixed(1);
      const row = document.createElement("div");
      row.className = "prob-row";
      row.innerHTML = `
        <span class="prob-name">${cls}</span>
        <div class="prob-track">
          <div class="prob-fill" style="width: ${pct}%; background: ${cls === data.prediction ? getSeverityColor(data.severity) : 'rgba(255,255,255,0.2)'}"></div>
        </div>
        <span class="prob-val">${pct}%</span>
      `;
      pContainer.appendChild(row);
    }
  }

  // CSOC Real-Time Alert Broadcast (No Mitigation)
  const sdnCard = document.getElementById("res-sdn-card");
  const sdnDesc = document.getElementById("res-sdn-action-desc");
  const openflowRule = document.getElementById("res-openflow-rule");

  if (data.prediction !== "Benign") {
    if (sdnCard) sdnCard.style.display = "block";
    const broadcastText = `ALERT_BROADCAST: Target=${payload.device_name} | Subtype=${data.prediction} | Severity=${data.severity} | Latency=0.96ms | SOC Webhook=SENT`;
    const explanation = `XGBoost Reconnaissance Alert Engine confirmed <strong>${data.prediction}</strong> probe targeting <code>${payload.destination_ip}</code>. High-priority clinical security alert dispatched to Hospital CSOC dashboard to enable proactive defense before weaponized exploit occurs.`;

    if (openflowRule) openflowRule.innerHTML = `<code>${broadcastText}</code>`;
    if (sdnDesc) sdnDesc.innerHTML = explanation;
  } else {
    if (sdnCard) sdnCard.style.display = "none";
  }
}

function updateTopologyDeviceStatus(presetKey, initialStatus, finalStatus) {
  const preset = PRESETS[presetKey];
  if (!preset || !preset.device_idx) return;

  const badge = document.getElementById(`status-dev-${preset.device_idx}`);
  if (!badge) return;

  if (finalStatus === "SAFE") {
    badge.textContent = "SAFE";
    badge.className = "device-status-badge status-safe";
  } else {
    badge.textContent = "ALERT: SCAN";
    badge.className = "device-status-badge status-scan";

    setTimeout(() => {
      badge.textContent = "SDN ISOLATED";
      badge.className = "device-status-badge status-quarantined";
    }, 1200);
  }
}

function getSeverityColor(sev) {
  switch (sev) {
    case "CRITICAL": return "var(--accent-rose)";
    case "HIGH": return "var(--accent-amber)";
    case "MEDIUM": return "var(--accent-blue)";
    case "LOW": return "var(--accent-cyan)";
    default: return "var(--accent-emerald)";
  }
}

// 5-Ward Hospital Batch Simulation
function initBatchButton() {
  document.getElementById("btn-run-batch-demo")?.addEventListener("click", async () => {
    const keys = ["port_scan", "os_scan", "vul_scan", "ping_sweep", "benign"];
    const flows = keys.map((k, idx) => ({
      ...PRESETS[k],
      flow_id: `DEMO-WARD-BATCH-${idx + 1}`,
    }));

    try {
      const res = await fetch("/predict/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flows }),
      });
      const data = await res.json();
      alert(`🏥 Hospital Subnet Batch Simulation Complete!\nProcessed ${data.count} IoMT flows in ${data.processing_time_ms} ms across 4 clinical wards.`);
      loadAlerts();
    } catch (e) {
      alert("Batch simulation error: " + e.message);
    }
  });
}

// Load Health & Metrics
async function loadHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      const data = await res.json();
      const statusText = document.getElementById("api-status-text");
      if (statusText) statusText.textContent = `SDN Edge IDS Online (${data.model_version})`;
    }
  } catch (e) {
    const statusText = document.getElementById("api-status-text");
    if (statusText) statusText.textContent = "SDN Edge Offline";
    document.getElementById("api-status-badge")?.classList.remove("live");
  }
}

// Load Persistent Alerts from /alerts
async function loadAlerts() {
  const tbody = document.getElementById("alerts-table-body");
  if (!tbody) return;

  try {
    const res = await fetch("/alerts?limit=15");
    if (!res.ok) throw new Error("Fetch failed");
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" class="text-center">No alerts logged in database yet. Run a scan scenario above to test!</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map((a) => {
      // Find matching device name from presets or IP
      let deviceLabel = "IoMT Clinical Node";
      for (const p of Object.values(PRESETS)) {
        if (p.destination_ip === a.destination_ip) {
          deviceLabel = `${p.device_name} (${p.ward_name})`;
          break;
        }
      }

      return `
        <tr>
          <td><code>${a.alert_id}</code></td>
          <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
          <td><strong>${deviceLabel}</strong></td>
          <td>${a.recon_subtype}</td>
          <td>${(a.confidence * 100).toFixed(1)}%</td>
          <td><span style="color:${getSeverityColor(a.severity)}; font-weight:700;">${a.severity}</span></td>
          <td><code>${a.source_ip || "-"}</code></td>
          <td><code>${a.destination_ip || "-"}</code></td>
          <td>${a.is_critical_asset ? "<span style='color:var(--accent-rose); font-weight:700;'>YES (ICU)</span>" : "NO"}</td>
          <td><span class="device-status-badge ${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'status-scan' : 'status-safe'}">🚨 NOTIFIED (CSOC)</span></td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted">Alerts load error: ${e.message}</td></tr>`;
  }
}
