'use strict';
// Set the SFileUp password. Enforces a strong password and stores only a hash.
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { hashPassword, problems } = require('./password');

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s === prompt) process.stdout.write(s); }; // hide typed characters
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write('\n'); resolve(answer); });
  });
}

(async () => {
  const pw = await ask('New password: ');
  const bad = problems(pw);
  if (bad.length) { console.error('Password too weak. Needs: ' + bad.join(', ')); process.exit(1); }
  if ((await ask('Confirm password: ')) !== pw) { console.error('Passwords do not match.'); process.exit(1); }
  fs.writeFileSync(path.join(__dirname, 'password.hash'), await hashPassword(pw));
  console.log('Saved password.hash');
})();
