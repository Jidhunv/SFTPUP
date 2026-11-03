'use strict';
// Minimal HTML templates; every interpolated value goes through esc().
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const flashHtml = (msgs) => msgs.map((m) => `<p class="${m.cat === 'ok' ? 'ok' : 'error'}">${esc(m.text)}</p>`).join('');

const layout = (flash, body) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SFileUp</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body><main>
${flashHtml(flash)}
${body}
</main></body>
</html>`;

const login = (flash, csrf) => layout(flash, `<h1>SFileUp</h1>
<form method="post" action="/login">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <input type="password" name="password" placeholder="Password" autofocus required autocomplete="current-password">
  <button>Sign in</button>
</form>`);

const upload = (flash, csrf, files) => layout(flash, `<h1>Upload archive</h1>
<form method="post" action="/upload" enctype="multipart/form-data">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <input type="file" name="file" accept=".zip,.rar" required>
  <button>Upload</button>
</form>
${files.length ? `<table>
  <tr><th>File</th><th>Size</th></tr>
  ${files.map((f) => `<tr><td>${esc(f.name)}</td><td>${(f.size / 1024).toFixed(1)} KB</td></tr>`).join('\n  ')}
</table>` : ''}
<form class="inline" method="post" action="/logout">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <button>Sign out</button>
</form>`);

module.exports = { login, upload };
