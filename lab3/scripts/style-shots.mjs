import fs from 'node:fs';
import path from 'node:path';

const img = path.resolve('sprawozdanie/img');
const css = fs.readFileSync('public/css/app.css', 'utf8');

function style(srcName, outName, bodyClass = '') {
  const raw = fs.readFileSync(path.join(img, srcName), 'utf8');
  const match = raw.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  const inner = match ? match[1] : raw;
  const html = `<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><style>
${css}
.hp{position:absolute!important;left:-10000px!important;width:1px;height:1px;overflow:hidden!important}
.side{display:none!important}
.shell{display:block}
.main{margin:0;width:100%;padding:1rem 1.5rem}
body{background:#efe8da;margin:0}
</style></head><body class="${bodyClass}">${inner}</body></html>`;
  fs.writeFileSync(path.join(img, outName), html);
  console.log('wrote', outName);
}

style('_no-captcha.html', 's02.html', 'auth');
style('_lockout.html', 's03.html', 'auth');
style('_canary.html', 's04.html', '');
style('_profile-password.html', 's05.html', '');
