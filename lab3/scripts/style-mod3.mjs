import fs from 'node:fs';
import path from 'node:path';

const img = path.resolve('sprawozdanie/img');
const css = fs.readFileSync('public/css/app.css', 'utf8');

function style(src, out) {
  if (!fs.existsSync(path.join(img, src))) {
    console.log('skip missing', src);
    return;
  }
  const raw = fs.readFileSync(path.join(img, src), 'utf8');
  const match = raw.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  const inner = match ? match[1] : raw;
  fs.writeFileSync(path.join(img, out), `<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><style>
${css}
.side{display:none!important}
.main{margin:0;width:100%;padding:1rem 1.5rem}
body{background:#efe8da;margin:0}
</style></head><body>${inner}</body></html>`);
  console.log('styled', out);
}

for (const [a, b] of [
  ['_dziennik.html', 's-dziennik.html'],
  ['_filtr.html', 's-filtr.html'],
  ['_verify-ok.html', 's-ok.html'],
  ['_verify-bad.html', 's-bad.html'],
  ['_alerty.html', 's-alerty.html'],
]) style(a, b);
