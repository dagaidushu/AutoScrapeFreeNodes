const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const scraper = require('./scraper');

const SUPPORTED_PROTOCOLS = new Set([
  'vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2',
  'hy2', 'tuic', 'socks', 'socks4', 'socks5', 'http', 'https',
  'wireguard', 'wg', 'anytls', 'naive', 'shadowtls'
]);

function decodeSubscription(content) {
  const raw = String(content || '').trim();
  if (!raw || raw.includes('://')) return raw;
  const compact = raw.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (compact.length < 16 || compact.length % 4 === 1 || !/^[A-Za-z0-9+/=]+$/.test(compact)) return raw;
  try {
    const decoded = Buffer.from(compact, 'base64').toString('utf8').trim();
    return decoded.includes('://') ? decoded : raw;
  } catch {
    return raw;
  }
}

function extractNodes(content) {
  return decodeSubscription(content)
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => {
      const match = line.match(/^([A-Za-z0-9+.-]+):\/\//);
      return match && SUPPORTED_PROTOCOLS.has(match[1].toLowerCase());
    });
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
  if (parsed.hostname !== 'node.freeclashnode.com' || !/\/\d+-\d{8}\.yaml$/i.test(parsed.pathname)) {
    return null;
  }
  parsed.pathname = parsed.pathname.replace(/\.yaml$/i, '.txt');
  return parsed.toString();
}

async function getManifestSubscriptionUrls(manifestUrls) {
  const urls = new Set();
  for (const manifestUrl of manifestUrls.filter(value => typeof value === 'string')) {
    try {
      const response = await axios.get(manifestUrl, {
        timeout: 20000,
        responseType: 'json',
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      for (const source of Object.values(response.data || {})) {
        for (const subscription of source.subscriptions || []) {
          if (typeof subscription.url === 'string' && /^https?:\/\//i.test(subscription.url)) {
            const subscriptionUrl = subscription.url.trim();
            urls.add(subscriptionUrl);
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

async function getSubscriptionUrls(dataDir, configuredSources, sourceTemplates, sourceManifestUrls) {
  const urls = new Set([
    ...configuredSources.filter(value => typeof value === 'string'),
    ...expandSourceTemplates(sourceTemplates)
  ]);
  if (fs.existsSync(dataDir)) {
    for (const file of fs.readdirSync(dataDir).filter(name => name.endsWith('.json'))) {
      const site = fs.readJsonSync(path.join(dataDir, file));
      for (const article of site.articles || []) {
        for (const subscription of article.subscriptions || []) {
          if (typeof subscription.url === 'string' && /^https?:\/\//i.test(subscription.url)) {
            urls.add(subscription.url.trim());
          }
        }
      }
    }
  }
  for (const url of await getManifestSubscriptionUrls(sourceManifestUrls)) urls.add(url);
  return [...urls];
}

async function fetchNodes(url, maxBytes) {
  const response = await axios.get(url, {
    timeout: 20000, responseType: 'text', maxContentLength: maxBytes, maxBodyLength: maxBytes,
    headers: { 'User-Agent': 'v2rayN/7.12.5' }, validateStatus: status => status >= 200 && status < 300
  });
  return extractNodes(response.data);
}

async function run() {
  const config = scraper.getConfig();
  const settings = config.settings || {};
  const dataDir = path.join(__dirname, settings.dataDir || 'data');
  const outputDir = path.join(__dirname, settings.outputDir || 'output');
  const maxSources = Number(settings.maxSubscriptionSources) || 30;
  const maxBytes = Number(settings.maxSubscriptionBytes) || 2 * 1024 * 1024;

  await scraper.scrapeAllSites();
  const sources = (await getSubscriptionUrls(
    dataDir,
    config.sourceSubscriptions || [],
    config.sourceTemplates || [],
    config.sourceManifestUrls || []
  )).slice(0, maxSources);
  const nodes = new Set();
  const failures = [];

  for (const source of sources) {
    try {
      const fetchedNodes = await fetchNodes(source, maxBytes);
      fetchedNodes.forEach(node => nodes.add(node));
      console.log(`${source}: ${fetchedNodes.length} nodes`);
    } catch (error) {
      failures.push({ url: source, error: error.message });
      console.warn(`${source}: ${error.message}`);
    }
  }

  const outputPath = path.join(outputDir, 'subscription.txt');
  await fs.ensureDir(outputDir);
  await fs.writeJson(path.join(outputDir, 'manifest.json'), {
    updatedAt: new Date().toISOString(), sourceCount: sources.length, nodeCount: nodes.size, failedSources: failures
  }, { spaces: 2 });
  if (nodes.size === 0) throw new Error('No valid nodes were collected. The previous subscription.txt was kept unchanged.');

  await fs.writeFile(outputPath, `${Buffer.from([...nodes].join('\n'), 'utf8').toString('base64')}\n`, 'utf8');
  console.log(`Wrote ${nodes.size} unique nodes to ${outputPath}`);
}

run().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
