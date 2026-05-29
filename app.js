var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');

var app = express();
var PORT = 3075;

// In-memory stores
var feedbackStore = [];
var sessions = {}; // token -> { username, mfaVerified }

function generateToken() {
  return Math.random().toString(36).substr(2) + Date.now().toString(36);
}

// Force X-Powered-By header on every response
app.use(function(req, res, next) {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// WAF middleware: blocks <script> tags only — SVG/event-handler vectors pass through
function wafMiddleware(req, res, next) {
  var body = JSON.stringify(req.body);
  if (/<script[\s\S]*?>/i.test(body)) {
    return res.status(403).json({
      error: 'Malicious content detected',
      message: 'Script tags are not allowed'
    });
  }
  next();
}

// Serve static files from public/
app.use(express.static(path.join(__dirname, 'public')));

// GET / — login page
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// POST /api/login — validates credentials, issues pre-MFA session cookie (HttpOnly=false)
// Vulnerability: cookie is issued BEFORE MFA is complete — theft via XSS allows MFA bypass
app.post('/api/login', function(req, res) {
  var username = req.body.username || '';
  var password = req.body.password || '';

  if (username === 'admin' && password === 'letmein') {
    var token = generateToken();
    sessions[token] = { username: 'admin', mfaVerified: false };
    res.cookie('pre_mfa_session', token, { httpOnly: false });
    return res.json({ status: 'mfa_required', redirect: '/mfa' });
  }

  return res.status(401).json({ error: 'Invalid credentials' });
});

// GET /mfa — MFA verification page
app.get('/mfa', function(req, res) {
  res.send(
    '<!DOCTYPE html>\n' +
    '<html lang="en">\n' +
    '<head>\n' +
    '  <meta charset="UTF-8">\n' +
    '  <title>MFA Verification</title>\n' +
    '  <style>\n' +
    '    * { box-sizing: border-box; margin: 0; padding: 0; }\n' +
    '    body { background: #0a0a0a; color: #00ff41; font-family: "Courier New", monospace;\n' +
    '           display: flex; justify-content: center; align-items: center; min-height: 100vh; }\n' +
    '    .container { width: 400px; padding: 40px; border: 1px solid #00ff41;\n' +
    '                 box-shadow: 0 0 20px rgba(0,255,65,0.3); }\n' +
    '    h1 { text-align: center; margin-bottom: 30px; font-size: 1.2rem; letter-spacing: 2px; }\n' +
    '    .form-group { margin-bottom: 20px; }\n' +
    '    label { display: block; margin-bottom: 6px; font-size: 0.85rem; color: #00cc33; }\n' +
    '    input[type="text"] { width: 100%; padding: 10px; background: #111;\n' +
    '      border: 1px solid #00ff41; color: #00ff41; font-family: "Courier New", monospace;\n' +
    '      font-size: 0.95rem; outline: none; letter-spacing: 4px; text-align: center; }\n' +
    '    button { width: 100%; padding: 12px; background: #00ff41; color: #0a0a0a;\n' +
    '      border: none; font-family: "Courier New", monospace; font-size: 1rem;\n' +
    '      font-weight: bold; cursor: pointer; letter-spacing: 1px; margin-top: 10px; }\n' +
    '    button:hover { background: #00cc33; }\n' +
    '    .hint { font-size: 0.75rem; color: #005500; margin-top: 20px; text-align: center; }\n' +
    '  </style>\n' +
    '</head>\n' +
    '<body>\n' +
    '  <div class="container">\n' +
    '    <h1>[ MFA VERIFICATION ]</h1>\n' +
    '    <form id="mfaForm">\n' +
    '      <div class="form-group">\n' +
    '        <label for="mfa_code">AUTHENTICATOR CODE</label>\n' +
    '        <input type="text" id="mfa_code" name="mfa_code" maxlength="6" placeholder="______" autocomplete="off" />\n' +
    '      </div>\n' +
    '      <button type="submit">&gt;&gt; VERIFY</button>\n' +
    '    </form>\n' +
    '    <p class="hint">Enter the 6-digit code from your authenticator app.</p>\n' +
    '  </div>\n' +
    '  <script>\n' +
    '    document.getElementById("mfaForm").addEventListener("submit", function(e) {\n' +
    '      e.preventDefault();\n' +
    '      var code = document.getElementById("mfa_code").value;\n' +
    '      fetch("/api/verify-mfa", {\n' +
    '        method: "POST",\n' +
    '        headers: { "Content-Type": "application/json" },\n' +
    '        body: JSON.stringify({ mfa_code: code })\n' +
    '      })\n' +
    '      .then(function(r) { return r.json(); })\n' +
    '      .then(function(data) {\n' +
    '        if (data.redirect) window.location.href = data.redirect;\n' +
    '        else alert(data.error || "Verification failed");\n' +
    '      });\n' +
    '    });\n' +
    '  </script>\n' +
    '</body>\n' +
    '</html>'
  );
});

// POST /api/verify-mfa — validates MFA code, upgrades session to fully authenticated
// Listed in robots.txt as Disallow — intended to hint attackers toward this endpoint
app.post('/api/verify-mfa', function(req, res) {
  var cookieHeader = req.headers.cookie || '';
  var match = cookieHeader.match(/pre_mfa_session=([^;]+)/);
  var token = match ? decodeURIComponent(match[1]) : null;
  var mfaCode = req.body.mfa_code || '';

  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'No active session. Please log in first.' });
  }

  if (mfaCode === '314159') {
    sessions[token].mfaVerified = true;
    res.cookie('adm_sess', token, { httpOnly: true });
    return res.json({ status: 'success', redirect: '/dashboard' });
  }

  return res.status(401).json({ error: 'Invalid MFA code' });
});

// GET /dashboard — intentional vulnerability: accepts pre_mfa_session without MFA verification
// Attack: steal pre_mfa_session via XSS (HttpOnly=false) → replay cookie → bypass MFA
app.get('/dashboard', function(req, res) {
  var cookieHeader = req.headers.cookie || '';

  var admMatch = cookieHeader.match(/adm_sess=([^;]+)/);
  var preMatch = cookieHeader.match(/pre_mfa_session=([^;]+)/);

  var token = admMatch ? decodeURIComponent(admMatch[1]) : (preMatch ? decodeURIComponent(preMatch[1]) : null);

  if (!token || !sessions[token]) {
    return res.redirect('/');
  }

  var session = sessions[token];

  var feedbackHTML = feedbackStore.map(function(f) {
    return '    <div class="xss-payload">' + f + '</div>';
  }).join('\n');

  res.send(
    '<html>\n' +
    '  <head><title>Admin Dashboard</title></head>\n' +
    '  <body>\n' +
    '    <h1>Admin Dashboard</h1>\n' +
    '    <p>Welcome, ' + session.username + '.</p>\n' +
    '    <p>MFA Status: ' + (session.mfaVerified ? 'Verified' : '<strong style="color:red">NOT VERIFIED — session hijacked?</strong>') + '</p>\n' +
    '    <p>Session Token: ' + token + '</p>\n' +
    '    <h2>Feedback History</h2>\n' +
    (feedbackHTML || '    <p>No feedback yet.</p>') + '\n' +
    '  </body>\n' +
    '</html>'
  );
});

// POST /api/feedback — WAF-checked, stored in memory, reflected back on dashboard (stored XSS)
app.post('/api/feedback', wafMiddleware, function(req, res) {
  var feedback = req.body.feedback || '';
  feedbackStore.push(feedback);
  res.json({
    status: 'success',
    message: 'Feedback received',
    data: { feedback: feedback }
  });
});

app.listen(PORT, function() {
  console.log('[*] CTF Lab server running on http://localhost:' + PORT);
});
