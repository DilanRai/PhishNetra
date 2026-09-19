const fs = require('fs');
const path = require('path');

const directories = [
  path.join(__dirname, 'src', 'pages'),
  path.join(__dirname, 'src', 'components')
];

function getTsxFiles(dir, fileList = []) {
  if (!fs.existsSync(dir)) return fileList;
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    if (fs.statSync(filePath).isDirectory()) {
      getTsxFiles(filePath, fileList);
    } else if (filePath.endsWith('.tsx')) {
      fileList.push(filePath);
    }
  }
  return fileList;
}

const fontReplacements = [
  { from: /'Syne', sans-serif/g, to: 'var(--font-sans)' },
  { from: /'DM Sans', sans-serif/g, to: 'var(--font-sans)' },
  { from: /'JetBrains Mono', monospace/g, to: 'var(--font-mono)' },
  { from: /'Poppins', sans-serif/g, to: 'var(--font-sans)' },
  { from: /'Inter', sans-serif/g, to: 'var(--font-sans)' }
];

const colorReplacements = [
  { from: /#00ff88/ig, to: '#34d399' },
  { from: /rgba\(0,\s*255,\s*136,/g, to: 'rgba(52,211,153,' },
  { from: /var\(--accent-green\)/g, to: 'var(--accent)' },

  { from: /#00d4ff/ig, to: '#60a5fa' },
  { from: /#00c4ff/ig, to: '#60a5fa' },
  { from: /rgba\(0,\s*212,\s*255,/g, to: 'rgba(96,165,250,' },
  { from: /rgba\(0,\s*196,\s*255,/g, to: 'rgba(96,165,250,' },
  { from: /var\(--accent-cyan\)/g, to: 'var(--color-info)' },

  { from: /#ff4444/ig, to: '#f87171' },
  { from: /rgba\(255,\s*68,\s*68,/g, to: 'rgba(248,113,113,' },
  { from: /var\(--accent-red\)/g, to: 'var(--color-danger)' },

  { from: /#f5a623/ig, to: '#fbbf24' },
  { from: /rgba\(245,\s*166,\s*35,/g, to: 'rgba(251,191,36,' },
  { from: /var\(--accent-yellow\)/g, to: '#fbbf24' },

  { from: /#f97316/ig, to: '#fb923c' },
  { from: /rgba\(249,\s*115,\s*22,/g, to: 'rgba(251,146,60,' }
];

const shadowReplacements = [
  { from: /boxShadow:\s*"0 0 40px rgba\(0,255,136,0\.5\)"/g, to: 'boxShadow: "var(--shadow-accent)"' },
  { from: /boxShadow:\s*'0 0 40px rgba\(0,255,136,0\.5\)'/g, to: "boxShadow: 'var(--shadow-accent)'" },
  
  { from: /boxShadow:\s*"0 0 24px rgba\(0,255,136,0\.35\)"/g, to: 'boxShadow: "var(--shadow-accent)"' },
  { from: /boxShadow:\s*'0 0 24px rgba\(0,255,136,0\.35\)'/g, to: "boxShadow: 'var(--shadow-accent)'" },
  
  { from: /boxShadow:\s*"0 0 20px rgba\(0,255,136,0\.4\)"/g, to: 'boxShadow: "var(--shadow-md)"' },
  { from: /boxShadow:\s*'0 0 20px rgba\(0,255,136,0\.4\)'/g, to: "boxShadow: 'var(--shadow-md)'" },
  
  { from: /boxShadow:\s*"0 0 8px rgba\(0,255,136,0\.5\)"/g, to: 'boxShadow: "none"' },
  { from: /boxShadow:\s*'0 0 8px rgba\(0,255,136,0\.5\)'/g, to: "boxShadow: 'none'" }
];

const bgReplacements = [
  { from: /#05080f/ig, to: '#080c14' },
  { from: /#080b10/ig, to: '#080c14' },
  { from: /var\(--bg-base\):\s*#05080f/ig, to: 'var(--bg-base): #080c14' }
];

const textShadowRegex1 = /.*textShadow:\s*`0 0 \d+px.*/g;
const textShadowRegex2 = /.*textShadow:\s*"0 0 .*/g;
const textShadowRegex3 = /.*textShadow:\s*'0 0 .*/g;

let files = [];
directories.forEach(dir => {
  files = getTsxFiles(dir, files);
});

console.log(`Found ${files.length} .tsx files.`);

for (const file of files) {
  let content = fs.readFileSync(file, 'utf8');
  let originalContent = content;

  fontReplacements.forEach(r => content = content.replace(r.from, r.to));
  colorReplacements.forEach(r => content = content.replace(r.from, r.to));
  shadowReplacements.forEach(r => content = content.replace(r.from, r.to));
  bgReplacements.forEach(r => content = content.replace(r.from, r.to));

  // Remove lines with specific text shadows
  let lines = content.split('\n');
  lines = lines.filter(line => !textShadowRegex1.test(line) && !textShadowRegex2.test(line) && !textShadowRegex3.test(line));
  content = lines.join('\n');

  if (content !== originalContent) {
    fs.writeFileSync(file, content, 'utf8');
    console.log(`Updated: ${file}`);
  }
}

console.log('Done replacing tokens.');
