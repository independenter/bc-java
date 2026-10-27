/**
 * 流程可视化审计 —— 校验 learning/build/traces 下的每个 HTML：
 *   1) 每个事件 group 都映射到流程图节点（无悬空 group）
 *   2) 复合 group（verify1:xxx）都有对应子步骤节点（光标跳得到）
 *   3) 节点首次出现的步骤号与流程图声明顺序一致（无回跳）
 *   4) 每个测试方法都有对应 HTML（无遗漏）
 *   5) 标题不与流程图名相同、不重复（用途标签有意义）
 *   6) 单文件事件数 ≤ 250（预算内）
 *   7) 测试 XML 里没有 [Tracer] 警告
 *
 * 退出码：0 全部通过；1 任一检查失败。CI 上 node 缺失时由 Gradle 跳过（见 build.gradle）。
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const traceDir = path.join(root, 'build', 'traces');
const resultDir = path.join(root, 'build', 'test-results');

function baseGroup(g) {
  const i = g.indexOf(':');
  return i < 0 ? g : g.slice(0, i);
}

function parseHtml(file) {
  const html = fs.readFileSync(path.join(traceDir, file), 'utf8');
  const h1 = (html.match(/<h1>([\s\S]*?)<\/h1>/) || [])[1] || '';
  const title = h1.replace(/<span class='flow-sub'>[\s\S]*?<\/span>/, '').trim();
  const flowName = ((html.match(/<span class='flow-sub'>流程图：([\s\S]*?)<\/span>/) || [])[1] || '').trim();

  const nodes = [];
  const nodeRe = /class='(flow-node[^']*|loop-wrapper)' data-group='([^']*)'/g;
  let m;
  while ((m = nodeRe.exec(html)) !== null) {
    nodes.push({ cls: m[1], group: m[2] });
  }

  const start = html.indexOf('const events = [');
  const from = html.indexOf('[', start);
  let depth = 0;
  let end = -1;
  for (let i = from; i < html.length; i++) {
    const c = html[i];
    if (c === '[') depth++;
    else if (c === ']') {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  const src = html.slice(from, end);
  const events = src.split(/\n  \},?\n/).map(chunk => {
    const step = (chunk.match(/step:\s*(\d+),/) || [])[1];
    const group = (chunk.match(/\n    group:\s*'([^']*)',/) || [])[1];
    return step && group ? { step: +step, group } : null;
  }).filter(Boolean);

  return { title, flowName, nodes, events };
}

function auditFile(file) {
  const issues = [];
  const { title, flowName, nodes, events } = parseHtml(file);

  if (!title) issues.push('无标题');
  if (title && title === flowName) issues.push('标题与流程图名相同: ' + title);

  const nodeGroups = new Set();
  const dup = new Set();
  nodes.forEach(n => {
    if (nodeGroups.has(n.group)) dup.add(n.group);
    nodeGroups.add(n.group);
  });
  if (dup.size) issues.push('重复节点 group: ' + [...dup].join(','));

  const unmapped = new Set();
  const missingSub = new Set();
  events.forEach(e => {
    const base = baseGroup(e.group);
    if (!nodeGroups.has(base)) unmapped.add(base);
    else if (e.group.includes(':') && !nodeGroups.has(e.group)) {
      const baseNode = nodes.find(n => n.group === base);
      if (baseNode && /flow-node-group/.test(baseNode.cls)) missingSub.add(e.group);
    }
  });
  if (unmapped.size) issues.push('未映射 group: ' + [...unmapped].join(','));
  if (missingSub.size) issues.push('缺子步骤节点: ' + [...missingSub].join(','));

  const firstStep = new Map();
  events.forEach(e => {
    const g = nodeGroups.has(e.group) ? e.group : baseGroup(e.group);
    if (nodeGroups.has(g) && !firstStep.has(g)) firstStep.set(g, e.step);
  });
  let last = -1;
  let lastGroup = null;
  const outOfOrder = [];
  nodes.forEach(n => {
    if (/flow-node-group/.test(n.cls)) return;
    const step = firstStep.get(n.group);
    if (step === undefined) return;
    if (step < last) outOfOrder.push(n.group + '(#' + step + ' < ' + lastGroup + ' #' + last + ')');
    else {
      last = step;
      lastGroup = n.group;
    }
  });
  if (outOfOrder.length) issues.push('顺序错乱: ' + outOfOrder.join(','));

  const steps = events.reduce((mx, e) => Math.max(mx, e.step), 0);
  if (steps === 0) issues.push('无事件');
  if (steps > 250) issues.push('事件数超预算: ' + steps);

  return { title, flowName, steps, issues };
}

if (!fs.existsSync(traceDir)) {
  console.log('[traceAudit] 未找到 traces 目录（' + traceDir + '）—— 跳过审计');
  process.exit(0);
}

// 只审计 essence 测试的 HTML（文件名以 essence 类名开头）
const essenceClasses = [
  'InteractiveCollaborativeSignatureEssenceTest',
  'MlDsaQuantumAnalysisTest',
  'MlKemQuantumAnalysisTest',
  'MultisigEssenceTest',
  'PqcEssenceTest',
  'QuantumResistanceAnalysisTest',
  'RsaEssenceTest',
  'SlhDsaEssenceTest',
  'Sm2EssenceTest',
  'Sm3EssenceTest',
  'Sm4EssenceTest',
  'Sm9EncryptEssenceTest',
  'Sm9ExchangeEssenceTest',
  'Sm9KeyEssenceTest',
  'Sm9PairingEssenceTest',
  'Sm9SignEssenceTest',
  'ThresholdEssenceTest',
];

const allFiles = fs.readdirSync(traceDir).filter(f => f.endsWith('.html'));
const files = allFiles.filter(f => essenceClasses.some(cls => f.startsWith(cls + '_')));
const skipped = allFiles.length - files.length;
if (skipped > 0) {
  console.log('[traceAudit] 跳过非 essence HTML: ' + skipped + ' 个');
}
const report = [];
let bad = 0;
let maxSteps = 0;
let maxFile = '';
for (const f of files) {
  const r = auditFile(f);
  if (r.issues.length) bad++;
  if (r.steps > maxSteps) {
    maxSteps = r.steps;
    maxFile = f;
  }
  report.push({ file: f, ...r });
}

console.log('[traceAudit] HTML 文件数: ' + files.length);
console.log('[traceAudit] 有问题文件数: ' + bad);
console.log('[traceAudit] 最大事件数: ' + maxSteps + (maxFile ? ' (' + maxFile + ')' : ''));
report.filter(r => r.issues.length).forEach(r => console.log('  [' + r.file + '] ' + r.issues.join(' | ')));

const sameName = report.filter(r => r.title && r.title === r.flowName);
console.log('[traceAudit] 标题==流程图名: ' + sameName.length);

const xmls = fs.existsSync(resultDir) ? fs.readdirSync(resultDir).filter(f => f.endsWith('.xml')) : [];
const methods = [];
for (const x of xmls) {
  // 只审计 essence 测试（带 @TraceExecution 的）；agreement/cipher/trace demo 不在范围内
  if (!/essence/i.test(x)) continue;
  const xml = fs.readFileSync(path.join(resultDir, x), 'utf8');
  for (const m of xml.matchAll(/<testcase name="([^"]+)" classname="([^"]+)"/g)) {
    methods.push(m[2].split('.').pop() + '_' + m[1] + '.html');
  }
}
const htmlSet = new Set(files);
const missingHtml = methods.filter(m => !htmlSet.has(m));
console.log('[traceAudit] 测试方法数: ' + methods.length + '，缺 HTML: ' + missingHtml.length);
missingHtml.slice(0, 20).forEach(m => console.log('  缺: ' + m));

const tracerWarnings = [];
for (const x of xmls) {
  // 只检查 essence 测试的警告；trace demo 测试的警告是预期的
  if (!/essence/i.test(x)) continue;
  const xml = fs.readFileSync(path.join(resultDir, x), 'utf8');
  const n = (xml.match(/\[Tracer\]/g) || []).length;
  if (n) tracerWarnings.push(x + ': ' + n);
}
console.log('[traceAudit] [Tracer] 警告: ' + (tracerWarnings.length ? tracerWarnings.join('; ') : '无'));

const titles = new Map();
report.forEach(r => {
  if (!r.title) return;
  if (!titles.has(r.title)) titles.set(r.title, []);
  titles.get(r.title).push(r.file);
});
const dupTitles = [...titles.entries()].filter(([, v]) => v.length > 1);
console.log('[traceAudit] 重复标题组: ' + dupTitles.length);
dupTitles.forEach(([t, v]) => console.log('  "' + t + '" -> ' + v.join(', ')));

const failures = bad + sameName.length + missingHtml.length + tracerWarnings.length + dupTitles.length;
if (failures > 0) {
  console.error('[traceAudit] 失败: ' + failures + ' 项检查未通过');
  process.exit(1);
}
console.log('[traceAudit] 全部通过 ✓');
