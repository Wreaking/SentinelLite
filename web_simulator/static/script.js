const validUser = 'sample_user';
const validPassword = 'ChangeMe123!';
const usernameField = document.getElementById('usernameField');
const passwordField = document.getElementById('passwordField');
const loginBtn = document.getElementById('loginBtn');
const loginResult = document.getElementById('loginResult');
const eventFeed = document.getElementById('eventFeed');
const startBtn = document.getElementById('startBtn');
const pauseBtn = document.getElementById('pauseBtn');
const stopBtn = document.getElementById('stopBtn');
const resetBtn = document.getElementById('resetBtn');
const scenarioCards = [...document.querySelectorAll('.scenario-card')];

let currentScenario = 'normal';
let simulationActive = false;
let pauseRequested = false;
let simulationTimer = null;

function addFeedEntry(text) {
  const item = document.createElement('div');
  item.className = 'feed-item';
  item.textContent = text;
  eventFeed.prepend(item);
  while (eventFeed.children.length > 12) {
    eventFeed.removeChild(eventFeed.lastChild);
  }
}

function getSpeedDelay() {
  const selected = document.querySelector('input[name="speed"]:checked')?.value || 'normal';
  const delays = { slow: 900, normal: 500, fast: 220 };
  return delays[selected] || 500;
}

function setScenario(scenario) {
  currentScenario = scenario;
  scenarioCards.forEach(card => {
    card.classList.toggle('active', card.dataset.scenario === scenario);
  });
  addFeedEntry(`[system] Selected scenario: ${scenario.replace('-', ' ')}`);
}

scenarioCards.forEach(card => {
  card.addEventListener('click', () => setScenario(card.dataset.scenario));
});

async function sendLoginRequest(username, password, sourceId = 'security_lab_browser', sourceType = 'local_simulator', target = 'security_lab_login') {
  const response = await fetch('/api/lab/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      password,
      source_ip: '127.0.0.1',
      source_id: sourceId,
      source_type: sourceType,
      target,
    })
  });
  return response.json();
}

async function triggerPortScan() {
  const ports = [22, 80, 443, 3306, 8080, 8443];
  for (const port of ports) {
    addFeedEntry(`[scan] Checking local service port ${port}`);
    await fetch('/api/lab/port-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_ip: '127.0.0.1',
        source_id: 'port_scan_simulator',
        source_type: 'local_simulator',
        ports: [port],
      })
    });
    await new Promise(resolve => setTimeout(resolve, getSpeedDelay()));
  }
}

async function triggerTrafficSpike() {
  addFeedEntry('[traffic] Starting local request burst');
  const requestCount = 35;
  for (let i = 0; i < requestCount; i += 1) {
    await fetch('/api/lab/traffic-spike', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_ip: '127.0.0.1',
        source_id: 'traffic_spike_simulator',
        source_type: 'local_simulator',
        request_count: 4,
        endpoint: '/lab/login',
      })
    });
    if (i % 10 === 0) {
      addFeedEntry(`[traffic] Burst request ${i + 1}/${requestCount}`);
    }
    await new Promise(resolve => setTimeout(resolve, 70));
  }
}

function typeInto(input, text) {
  return new Promise(resolve => {
    input.value = '';
    let index = 0;
    const tick = () => {
      input.value = text.slice(0, index + 1);
      index += 1;
      if (index < text.length) {
        setTimeout(tick, 80);
      } else {
        resolve();
      }
    };
    tick();
  });
}

async function humanLoginAttempt(username, password, resultLabel = 'Login failed') {
  await typeInto(usernameField, username);
  await typeInto(passwordField, password);
  loginBtn.click();
  const result = await sendLoginRequest(username, password, 'security_lab_browser', 'local_simulator', 'security_lab_login');
  if (result.authenticated) {
    loginResult.textContent = '✅ Valid local credential accepted';
    addFeedEntry(`[login] ${username} authenticated successfully`);
  } else {
    loginResult.textContent = `❌ ${result.message}`;
    addFeedEntry(`[login] ${username} -> ${result.message}`);
  }
  usernameField.value = '';
  passwordField.value = '';
  await new Promise(resolve => setTimeout(resolve, getSpeedDelay()));
}

async function runNormalScenario() {
  addFeedEntry('[normal] Baseline login test started');
  await humanLoginAttempt(validUser, validPassword, 'Valid local login');
}

async function runBruteForceScenario() {
  const passwords = ['sample-pass-1', 'sample-pass-2', 'sample-pass-3', 'sample-pass-4', 'sample-pass-5'];
  for (let i = 0; i < passwords.length; i += 1) {
    if (pauseRequested) return;
    addFeedEntry(`[bruteforce] Attempt ${i + 1}/${passwords.length}: admin / ${passwords[i]}`);
    await humanLoginAttempt('sample_admin', passwords[i]);
  }
}

async function runCredentialStuffingScenario() {
  const users = ['sample_user_1', 'sample_user_2', 'sample_user_3', 'sample_user_4', 'sample_user_5', 'sample_user'];
  for (let i = 0; i < users.length; i += 1) {
    if (pauseRequested) return;
    const username = users[i];
    addFeedEntry(`[credential-stuffing] Trying ${username} with local password set`);
    await humanLoginAttempt(username, 'SamplePassword123!', 'Credential stuffing attempt');
  }
}

async function runScenario() {
  if (!simulationActive) return;
  if (pauseRequested) {
    pauseRequested = false;
    return;
  }

  switch (currentScenario) {
    case 'normal':
      await runNormalScenario();
      break;
    case 'brute-force':
      await runBruteForceScenario();
      break;
    case 'credential-stuffing':
      await runCredentialStuffingScenario();
      break;
    case 'port-scan':
      await triggerPortScan();
      break;
    case 'traffic-spike':
      await triggerTrafficSpike();
      break;
    default:
      break;
  }

  if (simulationActive && !pauseRequested) {
    simulationTimer = setTimeout(runScenario, 300);
  }
}

async function startSimulation() {
  simulationActive = true;
  pauseRequested = false;
  addFeedEntry(`[system] Simulation started: ${currentScenario.replace('-', ' ')}`);
  if (simulationTimer) clearTimeout(simulationTimer);
  simulationTimer = setTimeout(runScenario, 300);
}

function pauseSimulation() {
  pauseRequested = true;
  addFeedEntry('[system] Simulation paused');
}

function resetSimulation() {
  simulationActive = false;
  pauseRequested = false;
  if (simulationTimer) clearTimeout(simulationTimer);
  usernameField.value = '';
  passwordField.value = '';
  loginResult.textContent = 'Ready for local simulation';
  addFeedEntry('[system] Security lab reset');
  fetch('/api/lab/reset', { method: 'POST' }).catch(() => {});
}

loginBtn.addEventListener('click', async () => {
  const username = usernameField.value.trim() || 'sample_user';
  const password = passwordField.value || 'ChangeMe123!';
  addFeedEntry(`[login] Manual login request for ${username}`);
  const result = await sendLoginRequest(username, password, 'security_lab_browser', 'local_simulator', 'security_lab_login');
  loginResult.textContent = result.authenticated ? '✅ Valid local credential accepted' : `❌ ${result.message}`;
});

startBtn.addEventListener('click', startSimulation);
pauseBtn.addEventListener('click', pauseSimulation);
stopBtn.addEventListener('click', resetSimulation);
resetBtn.addEventListener('click', resetSimulation);

setScenario(currentScenario);
