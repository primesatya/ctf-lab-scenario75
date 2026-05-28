var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');

var app = express();
var PORT = 3075;

// In-memory feedback store (persists for session, enables stored XSS)
var feedbackStore = [];

// Force X-Powered-By header on every response
app.use(function(req, res, next) {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set pre_mfa_session cookie on every request (HttpOnly=false so JS can read it)
app.use(function(req, res, next) {
  res.cookie('pre_mfa_session', 'pending_mfa_verification', {
    httpOnly: false
  });
  next();
});

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

// GET /dashboard — reflects stored feedback without sanitization
app.get('/dashboard', function(req, res) {
  var cookieHeader = req.headers.cookie || '';
  var match = cookieHeader.match(/pre_mfa_session=([^;]+)/);
  var sessionVal = match ? decodeURIComponent(match[1]) : 'pending_mfa_verification';

  var feedbackHTML = feedbackStore.map(function(f) {
    return '    <div class="xss-payload">' + f + '</div>';
  }).join('\n');

  res.send(
    '<html>\n' +
    '  <head><title>Admin Dashboard</title></head>\n' +
    '  <body>\n' +
    '    <h1>Admin Dashboard</h1>\n' +
    '    <p>Welcome to the admin area.</p>\n' +
    '    <p>Session Cookie: ' + sessionVal + '</p>\n' +
    '    <h2>Feedback History</h2>\n' +
    (feedbackHTML || '    <p>No feedback yet.</p>') + '\n' +
    '  </body>\n' +
    '</html>'
  );
});

// POST /api/feedback — WAF-checked, stored in memory, reflected back
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
