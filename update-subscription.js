const fs = require('fs-extra');
const net = require('net');
const path = require('path');
const axios = require('axios');
const scraper = require('./scraper');

const SUPPORTED_PROTOCOLS = new Set([
  'vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2',
  'hy2', 'tuic', 'socks', 'socks4', 'socks5', 'http', 'https',
  'wireguard', 'wg', 'anytls', 'naive', 'shadowtls'
]);

function decodeBase64(value) {
  const compact = String(value || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!compact || compact.length % 4 === 1 || !/^[A-Za-z0-9+/=]+$/.test(compact)) return null;
  try {
    return Buffer.from(compact, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function decodeSubscription(content) {
  const raw = String(content || '').trim();
  if (!raw || raw.includes('://')) return raw;
  const decoded = decodeBase64(raw.replace(/\s/g, ''));
  return decoded && decoded.includes('://') ? decoded.trim() : raw;
}

function getProtocol(node) {
  return (node.match(/^([A-Za-z0-9+.-]+):\/\//) || [])[1]?.toLowerCase() || null;
}

function extractNodes(content) {
  return decodeSubscription(content)
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => SUPPORTED_PROTOCOLS.has(getProtocol(line)));
}

function decodeVmess(node) {
  const content = decodeBase64(node.slice('vmess://'.length).split('#')[0]);
  if (!content) return null;
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function parseNodeTarget(node) {
  const protocol = getProtocol(node);
  if (!protocol) return null;

  if (protocol === 'vmess') {
    const config = decodeVmess(node);
    if (!config?.add || !config?.port) return null;
    return { host: String(config.add), port: Number(config.port) };
  }

  if (protocol === 'ssr') {
    const decoded = decodeBase64(node.slice('ssr://'.length));
    const endpoint = decoded?.split('/?')[0];
    const match = endpoint?.match(/^\[?([^\]:]+)\]?:([0-9]+)/);
    return match ? { host: match[1], port: Number(match[2]) } : null;
  }

  try {
    const url = new URL(node);
    const port = Number(url.port) || (protocol === 'http' ? 80 : 443);
    return url.hostname ? { host: url.hostname, port } : null;
  } catch {
    if (protocol !== 'ss') return null;
    const match = node.match(/^ss:\/\/(?:[^@]+@)?([^:/#?]+):(\d+)/i);
    return match ? { host: match[1], port: Number(match[2]) } : null;
  }
}

function semanticKey(node) {
  const protocol = getProtocol(node);
  if (protocol === 'vmess') {
    const config = decodeVmess(node);
    if (config) {
      return JSON.stringify({
        protocol, host: config.add, port: config.port, id: config.id, aid: config.aid,
        net: config.net, type: config.type, hostHeader: config.host, path: config.path,
        tls: config.tls, sni: config.sni, alpn: config.alpn, fp: config.fp, pbk: config.pbk, sid: config.sid
      });
    }
  }

  if (protocol === 'ssr') {
    const decoded = decodeBase64(node.slice('ssr://'.length));
    return decoded ? `${protocol}:${decoded.split('/?')[0]}` : node;
  }

  try {
    const url = new URL(node);
    url.hash = '';
    const ignored = new Set(['remarks', 'remark', 'name', 'ps']);
    const query = [...url.searchParams.entries()]
      .filter(([key]) => !ignored.has(key.toLowerCase()))
      .sort(([left], [right]) => left.localeCompare(right));
    url.search = new URLSearchParams(query).toString();
    return `${protocol}:${url.toString()}`;
  } catch {
    return node;
  }
}

function expandSourceTemplates(templates) {
  const dateParts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(new Date()).reduce((parts, part) => {
    parts[part.type] = part.value;
    return parts;
  }, {});
  const replacements = {
    '{YYYY}': dateParts.year,
    '{MM}': dateParts.month,
    '{DD}': dateParts.day
  };
  replacements['{YYYYMMDD}'] = `${replacements['{YYYY}']}${replacements['{MM}']}${replacements['{DD}']}`;

  return templates.filter(value => typeof value === 'string').map(template =>
    Object.entries(replacements).reduce((value, [token, replacement]) => value.replaceAll(token, replacement), template)
  );
}

function getGenericTextVariant(url) {
  const parsed = new URL(url);
  if (parsed.hostname !== 'node.freeclashnode.com' || !/\/\d+-\d{8}\.yaml$/i.test(parsed.pathname)) return null;
  parsed.pathname = parsed.pathname.replace(/\.yaml$/i, '.txt');
  return parsed.toString();
}

async function getManifestSubscriptionUrls(manifestUrls) {
  const urls = new Set();
  for (const manifestUrl of manifestUrls.filter(value => typeof value === 'string')) {
    try {
      const response = await getWithRetry(manifestUrl, {
        timeout: 20000, responseType: 'json', headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      for (const source of Object.values(response.data || {})) {
        for (const subscription of source.subscriptions || []) {
          if (typeof subscription.url !== 'string' || !/^https?:\/\//i.test(subscription.url)) continue;
          const subscriptionUrl = subscription.url.trim();
          const type = String(subscription.type || '').toLowerCase();
          if (type === 'v2ray') urls.add(subscriptionUrl);
          else if (type === 'clash') {
            const genericTextVariant = getGenericTextVariant(subscriptionUrl);
            if (genericTextVariant) urls.add(genericTextVariant);
          }
        }
      }
      console.log(`${manifestUrl}: found ${urls.size} subscription sources`);
    } catch (error) {
      console.warn(`${manifestUrl}: ${error.message}`);
    }
  }
  return urls;
}

async function getSubscriptionUrls(configuredSources, sourceTemplates, sourceManifestUrls) {
  const urls = new Set([
    ...configuredSources.filter(value => typeof value === 'string'),
    ...expandSourceTemplates(sourceTemplates)
  ]);
  for (const url of await getManifestSubscriptionUrls(sourceManifestUrls)) urls.add(url);
  return [...urls];
}

async function fetchNodes(url, maxBytes) {
  let lastError;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0',
          Accept: 'text/plain,*/*'
        }
      });
      if (!response.ok) throw new Error(`Request failed with status code ${response.status}`);
      const declaredLength = Number(response.headers.get('content-length'));
      if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        throw new Error(`Subscription exceeds ${maxBytes} bytes`);
      }
      const content = new Uint8Array(await response.arrayBuffer());
      if (content.byteLength > maxBytes) throw new Error(`Subscription exceeds ${maxBytes} bytes`);
      const nodes = extractNodes(new TextDecoder().decode(content));
      if (nodes.length === 0) throw new Error('Response contains no supported node URIs');
      return nodes;
    } catch (error) {
      lastError = error?.name === 'AbortError' ? new Error('Request timed out after 20000ms') : error;
      if (attempt === 1) console.warn(`${url}: first request failed, retrying once`);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError;
}

async function getWithRetry(url, options) {
  let lastError;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      return await axios.get(url, options);
    } catch (error) {
      lastError = error;
      if (attempt === 1) console.warn(`${url}: first request failed, retrying once`);
    }
  }
  throw lastError;
}

function probeTarget({ host, port }, timeoutMs) {
  return new Promise(resolve => {
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
      resolve({ status: 'skipped', reason: 'invalid endpoint' });
      return;
    }
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish({ status: 'reachable' }));
    socket.once('timeout', () => finish({ status: 'unreachable', reason: 'timeout' }));
    socket.once('error', error => finish({ status: 'unreachable', reason: error.code || error.message }));
  });
}

async function mapWithConcurrency(items, concurrency, operation) {
  const results = new Array(items.length);
  let index = 0;
  async function worker() {
    while (true) {
      const current = index++;
      if (current >= items.length) return;
      results[current] = await operation(items[current]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

async function filterReachableNodes(nodes, checkSettings) {
  if (!checkSettings.enabled) {
    return { nodes, checked: 0, unreachable: 0, skipped: 0, enabled: false };
  }
  const targets = new Map();
  for (const node of nodes) {
    const target = parseNodeTarget(node);
    if (target) targets.set(`${target.host}:${target.port}`, target);
  }
  const results = new Map();
  await mapWithConcurrency([...targets.entries()], Math.max(1, Number(checkSettings.concurrency) || 32), async ([key, target]) => {
    results.set(key, await probeTarget(target, Math.max(500, Number(checkSettings.timeoutMs) || 3000)));
  });

  let unreachable = 0;
  let skipped = 0;
  const kept = nodes.filter(node => {
    const target = parseNodeTarget(node);
    if (!target) {
      skipped += 1;
      return true;
    }
    const result = results.get(`${target.host}:${target.port}`);
    if (result?.status === 'unreachable') {
      unreachable += 1;
      return false;
    }
    if (result?.status === 'skipped') skipped += 1;
    return true;
  });
  return { nodes: kept, checked: targets.size, unreachable, skipped, enabled: true };
}

function toSubscription(nodes) {
  return `${Buffer.from(nodes.join('\n'), 'utf8').toString('base64')}\n`;
}

async function writeProtocolSubscriptions(outputDir, nodes) {
  const grouped = new Map();
  for (const node of nodes) {
    const protocol = getProtocol(node);
    if (!grouped.has(protocol)) grouped.set(protocol, []);
    grouped.get(protocol).push(node);
  }
  for (const protocol of SUPPORTED_PROTOCOLS) {
    const outputPath = path.join(outputDir, `${protocol}.txt`);
    const protocolNodes = grouped.get(protocol) || [];
    if (protocolNodes.length) await fs.writeFile(outputPath, toSubscription(protocolNodes), 'utf8');
    else await fs.remove(outputPath);
  }
  return Object.fromEntries([...grouped.entries()].map(([protocol, protocolNodes]) => [protocol, protocolNodes.length]));
}

async function run() {
  const config = scraper.getConfig();
  const settings = config.settings || {};
  const outputDir = path.join(__dirname, settings.outputDir || 'output');
  const maxSources = Number(settings.maxSubscriptionSources) || 30;
  const maxBytes = Number(settings.maxSubscriptionBytes) || 2 * 1024 * 1024;
  const connectivityCheck = {
    enabled: settings.connectivityCheck?.enabled !== false,
    timeoutMs: settings.connectivityCheck?.timeoutMs || 3000,
    concurrency: settings.connectivityCheck?.concurrency || 32
  };

  await scraper.scrapeAllSites();
  const sources = (await getSubscriptionUrls(
    config.sourceSubscriptions || [],
    config.sourceTemplates || [],
    config.sourceManifestUrls || []
  )).slice(0, maxSources);
  const exactNodes = new Set();
  const sourceResults = [];
  const sourceNodeGroups = new Array(sources.length).fill(null);

  for (const [sourceIndex, source] of sources.entries()) {
    const outputFile = `source-${sourceIndex + 1}.txt`;
    try {
      const fetchedNodes = await fetchNodes(source, maxBytes);
      fetchedNodes.forEach(node => exactNodes.add(node));
      sourceNodeGroups[sourceIndex] = [...new Set(fetchedNodes)];
      sourceResults.push({
        url: source,
        outputFile,
        status: 'ok',
        extractedNodes: fetchedNodes.length,
        uniqueNodes: sourceNodeGroups[sourceIndex].length
      });
      console.log(`${source}: ${fetchedNodes.length} nodes`);
    } catch (error) {
      sourceResults.push({ url: source, outputFile, status: 'failed', error: error.message });
      console.warn(`${source}: ${error.message}`);
    }
  }

  await fs.ensureDir(outputDir);
  for (const [sourceIndex, sourceNodes] of sourceNodeGroups.entries()) {
    const sourceOutputPath = path.join(outputDir, `source-${sourceIndex + 1}.txt`);
    if (sourceNodes) {
      await fs.writeFile(sourceOutputPath, toSubscription(sourceNodes), 'utf8');
    } else if (!(await fs.pathExists(sourceOutputPath))) {
      await fs.writeFile(sourceOutputPath, toSubscription([]), 'utf8');
    }
  }
  await fs.writeJson(path.join(outputDir, 'source-manifest.json'), {
    updatedAt: new Date().toISOString(),
    sources: sourceResults
  }, { spaces: 2 });
  await Promise.all([1, 2, 3].map(index => fs.remove(path.join(outputDir, `subscription-${index}.txt`))));

  const successfulSourceCount = sourceResults.filter(result => result.status === 'ok').length;
  const minimumSuccessfulSources = Math.max(1, Math.ceil(sources.length * 0.6));
  if (successfulSourceCount < minimumSuccessfulSources) {
    await fs.ensureDir(outputDir);
    await fs.writeJson(path.join(outputDir, 'failed-run.json'), {
      updatedAt: new Date().toISOString(),
      sourceCount: sources.length,
      successfulSourceCount,
      minimumSuccessfulSources,
      sourceResults,
      message: 'Too few sources succeeded. Per-source files were updated independently; aggregate files were kept unchanged.'
    }, { spaces: 2 });
    console.warn(`Only ${successfulSourceCount}/${sources.length} sources succeeded; aggregate files require ${minimumSuccessfulSources}.`);
    return;
  }

  const semanticNodes = new Map();
  for (const node of exactNodes) {
    const key = semanticKey(node);
    if (!semanticNodes.has(key)) semanticNodes.set(key, node);
  }
  const deduplicatedNodes = [...semanticNodes.values()];
  const health = await filterReachableNodes(deduplicatedNodes, connectivityCheck);
  const nodes = health.nodes;
  const protocolCounts = Object.fromEntries([...SUPPORTED_PROTOCOLS].map(protocol => [protocol, 0]));
  for (const node of nodes) protocolCounts[getProtocol(node)] += 1;

  await fs.ensureDir(outputDir);
  const manifest = {
    updatedAt: new Date().toISOString(),
    sourceCount: sources.length,
    sourceResults,
    counts: {
      extracted: [...sourceResults].filter(result => result.status === 'ok').reduce((total, result) => total + result.extractedNodes, 0),
      exactUnique: exactNodes.size,
      semanticUnique: deduplicatedNodes.length,
      semanticDuplicatesRemoved: exactNodes.size - deduplicatedNodes.length,
      reachableNodes: nodes.length,
      unreachableNodesRemoved: health.unreachable
    },
    connectivityCheck: {
      enabled: health.enabled,
      checkedEndpoints: health.checked,
      unparseableNodesKept: health.skipped,
      timeoutMs: connectivityCheck.timeoutMs,
      concurrency: connectivityCheck.concurrency
    },
    protocolCounts,
    failedSources: sourceResults.filter(result => result.status === 'failed').map(({ url, error }) => ({ url, error }))
  };
  if (nodes.length === 0) {
    await fs.writeJson(path.join(outputDir, 'failed-run.json'), {
      updatedAt: manifest.updatedAt,
      sourceCount: manifest.sourceCount,
      sourceResults: manifest.sourceResults,
      message: 'No usable nodes were collected. The previous successful output was kept unchanged.'
    }, { spaces: 2 });
    throw new Error('No usable nodes were collected. The previous subscription.txt and manifest.json were kept unchanged.');
  }
  await fs.writeJson(path.join(outputDir, 'manifest.json'), manifest, { spaces: 2 });
  await fs.remove(path.join(outputDir, 'failed-run.json'));

  const historyPath = path.join(outputDir, 'history.json');
  const previousHistory = await fs.readJson(historyPath).catch(() => []);
  const history = Array.isArray(previousHistory) ? previousHistory : [];
  history.push({
    updatedAt: manifest.updatedAt,
    sourceCount: manifest.sourceCount,
    nodeCount: nodes.length,
    unreachableNodesRemoved: health.unreachable,
    failedSourceCount: manifest.failedSources.length,
    protocolCounts
  });
  const historyLimit = Math.max(1, Number(settings.historyLimit) || 30);
  await fs.writeJson(historyPath, history.slice(-historyLimit), { spaces: 2 });
  await fs.writeFile(path.join(outputDir, 'subscription.txt'), toSubscription(nodes), 'utf8');
  await writeProtocolSubscriptions(outputDir, nodes);
  console.log(`Wrote ${nodes.length} semantically unique aggregate nodes and ${successfulSourceCount} per-source subscriptions`);
}

run().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
