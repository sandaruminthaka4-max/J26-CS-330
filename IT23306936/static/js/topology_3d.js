/**
 * IoMT Hospital Network Topology Visualization (3D WebGL + 2D Fallback)
 * Component: Safety-Constrained Adaptive SDN Mitigation and Monitoring (IT23306936)
 * 
 * NOTE: Animations are illustrative representations of network state;
 * they are NOT presented as packet-level empirical evidence.
 */

let currentViewMode = '3D';
let threeRenderer = null, threeScene = null, threeCamera = null;
let animFrameId = null;

// Topology Nodes & Particle Systems
let nodeMeshes = {};
let particles = {
    sensor: [],
    attacker: []
};

let currentNetworkState = {
    sensorThroughput: 100.0,
    sensorLoss: 0.0,
    mitigationAction: 'none',
    rateLimitKbps: null,
    threatActive: false
};

document.addEventListener('DOMContentLoaded', () => {
    initTopology();
});

function initTopology() {
    const wrapper = document.getElementById('threejs-canvas-wrapper');
    if (!wrapper) return;

    // Check if Three.js loaded and WebGL available
    if (window.THREE && isWebGLAvailable()) {
        try {
            init3DScene(wrapper);
        } catch (e) {
            console.warn("WebGL initialization failed, falling back to 2D:", e);
            setTopologyView('2D');
        }
    } else {
        console.warn("Three.js not available, using 2D canvas fallback");
        setTopologyView('2D');
    }
}

function isWebGLAvailable() {
    try {
        const canvas = document.createElement('canvas');
        return !!(window.WebGLRenderingContext && (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')));
    } catch (e) {
        return false;
    }
}

function setTopologyView(mode) {
    currentViewMode = mode;
    const btn3D = document.getElementById('btn-view-3d');
    const btn2D = document.getElementById('btn-view-2d');
    const wrapper3D = document.getElementById('threejs-canvas-wrapper');
    const canvas2D = document.getElementById('canvas-2d-topology');

    if (mode === '3D') {
        if (btn3D) btn3D.classList.add('active');
        if (btn2D) btn2D.classList.remove('active');
        if (wrapper3D) wrapper3D.style.display = 'block';
        if (canvas2D) canvas2D.style.display = 'none';
        if (!threeRenderer && window.THREE) {
            initTopology();
        }
    } else {
        if (btn3D) btn3D.classList.remove('active');
        if (btn2D) btn2D.classList.add('active');
        if (wrapper3D) wrapper3D.style.display = 'none';
        if (canvas2D) {
            canvas2D.style.display = 'block';
            draw2DTopology();
        }
    }
}

// ==============================================================================
// 3D Scene Implementation (Three.js)
// ==============================================================================

function init3DScene(container) {
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 380;

    threeScene = new THREE.Scene();
    threeScene.background = new THREE.Color(0x0a101d);

    threeCamera = new THREE.PerspectiveCamera(45, width / height, 1, 1000);
    threeCamera.position.set(0, 180, 360);
    threeCamera.lookAt(0, 10, 0);

    // Subtle Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    threeScene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x38bdf8, 0.8);
    dirLight.position.set(100, 200, 150);
    threeScene.add(dirLight);

    const pointLight = new THREE.PointLight(0x6366f1, 1.2, 500);
    pointLight.position.set(0, 80, 0);
    threeScene.add(pointLight);

    // Floor Grid (Hospital Ward Floor)
    const gridHelper = new THREE.GridHelper(400, 20, 0x1e293b, 0x0f172a);
    gridHelper.position.y = -20;
    threeScene.add(gridHelper);

    // Create 3D Nodes
    create3DNodes();

    // Create Connection Cables / Pipelines
    create3DCables();

    // Create Particle Packets
    createParticleSystem();

    threeRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    threeRenderer.setSize(width, height);
    threeRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = '';
    container.appendChild(threeRenderer.domElement);

    // Animation Loop
    let angle = 0;
    function animate() {
        animFrameId = requestAnimationFrame(animate);

        // Gentle camera float
        angle += 0.002;
        threeCamera.position.x = Math.sin(angle) * 350;
        threeCamera.position.z = Math.cos(angle) * 350;
        threeCamera.lookAt(0, 15, 0);

        // Update animated particles
        animateParticles();

        threeRenderer.render(threeScene, threeCamera);
    }
    animate();

    window.addEventListener('resize', () => {
        if (!container || !threeRenderer || !threeCamera) return;
        const w = container.clientWidth;
        const h = container.clientHeight;
        threeCamera.aspect = w / h;
        threeCamera.updateProjectionMatrix();
        threeRenderer.setSize(w, h);
    });
}

function create3DNodes() {
    // 1. h1 Medical Sensor / Bed (Cyan/Green)
    const sensorGeo = new THREE.BoxGeometry(40, 24, 30);
    const sensorMat = new THREE.MeshPhongMaterial({ color: 0x06b6d4, emissive: 0x0284c7, emissiveIntensity: 0.3 });
    const h1Mesh = new THREE.Mesh(sensorGeo, sensorMat);
    h1Mesh.position.set(-140, 0, 40);
    threeScene.add(h1Mesh);
    nodeMeshes['h1'] = h1Mesh;

    // 2. s1 SDN OpenFlow Switch (Indigo Cube with status LED)
    const switchGeo = new THREE.CylinderGeometry(28, 28, 20, 16);
    const switchMat = new THREE.MeshPhongMaterial({ color: 0x312e81, emissive: 0x4338ca, emissiveIntensity: 0.4 });
    const s1Mesh = new THREE.Mesh(switchGeo, switchMat);
    s1Mesh.position.set(0, 0, 0);
    threeScene.add(s1Mesh);
    nodeMeshes['s1'] = s1Mesh;

    // 3. h2 Hospital Edge Server (Violet Tower)
    const serverGeo = new THREE.BoxGeometry(32, 60, 32);
    const serverMat = new THREE.MeshPhongMaterial({ color: 0x7c3aed, emissive: 0x6d28d9, emissiveIntensity: 0.3 });
    const h2Mesh = new THREE.Mesh(serverGeo, serverMat);
    h2Mesh.position.set(140, 15, 40);
    threeScene.add(h2Mesh);
    nodeMeshes['h2'] = h2Mesh;

    // 4. h3 Attacker Terminal (Red Cube)
    const attackerGeo = new THREE.BoxGeometry(36, 22, 26);
    const attackerMat = new THREE.MeshPhongMaterial({ color: 0xef4444, emissive: 0xb91c1c, emissiveIntensity: 0.4 });
    const h3Mesh = new THREE.Mesh(attackerGeo, attackerMat);
    h3Mesh.position.set(-140, 0, -80);
    threeScene.add(h3Mesh);
    nodeMeshes['h3'] = h3Mesh;

    // 5. c0 Controller (Gold Sphere Hovering Above Switch)
    const ctrlGeo = new THREE.SphereGeometry(14, 16, 16);
    const ctrlMat = new THREE.MeshPhongMaterial({ color: 0xf59e0b, emissive: 0xd97706, emissiveIntensity: 0.5 });
    const c0Mesh = new THREE.Mesh(ctrlGeo, ctrlMat);
    c0Mesh.position.set(0, 65, 0);
    threeScene.add(c0Mesh);
    nodeMeshes['c0'] = c0Mesh;
}

function create3DCables() {
    function addCable(from, to, color) {
        const points = [from, to];
        const path = new THREE.LineCurve3(from, to);
        const tubeGeo = new THREE.TubeGeometry(path, 8, 2, 8, false);
        const tubeMat = new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.45 });
        const mesh = new THREE.Mesh(tubeGeo, tubeMat);
        threeScene.add(mesh);
    }

    addCable(new THREE.Vector3(-140, 0, 40), new THREE.Vector3(0, 0, 0), 0x06b6d4); // h1 -> s1
    addCable(new THREE.Vector3(-140, 0, -80), new THREE.Vector3(0, 0, 0), 0xef4444); // h3 -> s1
    addCable(new THREE.Vector3(0, 0, 0), new THREE.Vector3(140, 15, 40), 0x10b981); // s1 -> h2
    addCable(new THREE.Vector3(0, 65, 0), new THREE.Vector3(0, 10, 0), 0xf59e0b); // c0 -> s1
}

function createParticleSystem() {
    const pGeo = new THREE.SphereGeometry(2.5, 8, 8);

    // Sensor particles (h1 -> s1 -> h2)
    const sensorMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8 });
    for (let i = 0; i < 20; i++) {
        const mesh = new THREE.Mesh(pGeo, sensorMat);
        mesh.userData = { progress: i / 20.0, speed: 0.008 };
        threeScene.add(mesh);
        particles.sensor.push(mesh);
    }

    // Attacker particles (h3 -> s1)
    const attackerMat = new THREE.MeshBasicMaterial({ color: 0xef4444 });
    for (let i = 0; i < 30; i++) {
        const mesh = new THREE.Mesh(pGeo, attackerMat);
        mesh.userData = { progress: i / 30.0, speed: 0.015 };
        threeScene.add(mesh);
        particles.attacker.push(mesh);
    }
}

function animateParticles() {
    const p1 = new THREE.Vector3(-140, 0, 40); // h1
    const s1 = new THREE.Vector3(0, 0, 0);      // s1
    const p2 = new THREE.Vector3(140, 15, 40);  // h2
    const p3 = new THREE.Vector3(-140, 0, -80); // h3

    // Animate sensor traffic (h1 -> s1 -> h2)
    particles.sensor.forEach(p => {
        p.userData.progress += p.userData.speed;
        if (p.userData.progress > 1.0) p.userData.progress = 0;

        const prog = p.userData.progress;
        if (prog < 0.5) {
            p.position.lerpVectors(p1, s1, prog * 2);
        } else {
            p.position.lerpVectors(s1, p2, (prog - 0.5) * 2);
        }
    });

    // Animate attacker traffic (h3 -> s1, then dropped or metered)
    const isBlocked = (currentNetworkState.mitigationAction === 'block');
    const isMetered = (currentNetworkState.mitigationAction === 'rate_limit');

    particles.attacker.forEach(p => {
        p.userData.progress += p.userData.speed;
        if (p.userData.progress > 1.0) p.userData.progress = 0;

        const prog = p.userData.progress;
        if (prog < 0.6) {
            p.position.lerpVectors(p3, s1, prog / 0.6);
            p.visible = true;
        } else {
            if (isBlocked) {
                // Completely dropped at switch
                p.visible = false;
            } else if (isMetered) {
                // Rate limited: 75% dropped, 25% forwarded as amber particles
                if (Math.random() < 0.75) {
                    p.visible = false;
                } else {
                    p.visible = true;
                    p.position.lerpVectors(s1, p2, (prog - 0.6) / 0.4);
                }
            } else {
                // Unmitigated: flows through to bottleneck
                p.position.lerpVectors(s1, p2, (prog - 0.6) / 0.4);
                p.visible = true;
            }
        }
    });
}

// Hook called by dashboard.js on each telemetry update
window.updateTopologyState = function(data) {
    if (!data) return;
    currentNetworkState.sensorThroughput = Number(data.sensor_throughput_kbps) || 0;
    currentNetworkState.sensorLoss = Number(data.sensor_packet_loss_percent) || 0;
    currentNetworkState.mitigationAction = data.mitigation_action || 'none';
    currentNetworkState.rateLimitKbps = data.rate_limit_kbps;

    if (currentViewMode === '2D') {
        draw2DTopology();
    }
};

// ==============================================================================
// 2D Canvas Fallback View
// ==============================================================================

function draw2DTopology() {
    const canvas = document.getElementById('canvas-2d-topology');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth;
    const h = canvas.height = canvas.clientHeight;

    ctx.clearRect(0, 0, w, h);

    // Node Positions
    const h1 = { x: w * 0.18, y: h * 0.35, label: "h1 (ECG Sensor)", ip: "10.0.0.1", color: "#06b6d4" };
    const h3 = { x: w * 0.18, y: h * 0.75, label: "h3 (Attacker)", ip: "10.0.0.3", color: "#ef4444" };
    const s1 = { x: w * 0.50, y: h * 0.55, label: "s1 (SDN Switch)", ip: "OpenFlow 1.3", color: "#6366f1" };
    const c0 = { x: w * 0.50, y: h * 0.18, label: "c0 (SDN Control Plane)", ip: "Direct OVS Active (Ryu Open Req)", color: "#f59e0b" };
    const h2 = { x: w * 0.82, y: h * 0.55, label: "h2 (Edge Server)", ip: "10.0.0.2:5201/2", color: "#10b981" };

    // Draw Links
    function drawLink(from, to, text, isBottleneck) {
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = isBottleneck ? '#f59e0b' : 'rgba(255, 255, 255, 0.2)';
        ctx.lineWidth = isBottleneck ? 3.5 : 2;
        ctx.stroke();

        // Label
        const midX = (from.x + to.x) / 2;
        const midY = (from.y + to.y) / 2;
        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(text, midX, midY - 6);
    }

    drawLink(h1, s1, "10 Mbps (ECG)", false);
    drawLink(h3, s1, "10 Mbps (5M DoS)", false);
    drawLink(c0, s1, "Direct OVS OF1.3", false);
    drawLink(s1, h2, "2 Mbps Bottleneck", true);

    // Draw Nodes
    function drawNode(node) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 20, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 11px Outfit, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + 32);

        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.fillText(node.ip, node.x, node.y + 44);
    }

    drawNode(h1);
    drawNode(h3);
    drawNode(s1);
    drawNode(c0);
    drawNode(h2);
}
