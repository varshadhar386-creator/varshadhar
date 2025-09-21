// server.js
const express = require('express');
const fetch = require('node-fetch');
const dns = require('dns').promises;
const whois = require('whois-json');
const NodeCache = require('node-cache');

const app = express();
const cache = new NodeCache({ stdTTL: 60 * 5, checkperiod: 120 }); // cache 5 mins

// Load API keys from Railway environment variables
const VT_API_KEY = process.env.VT_API_KEY;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
const IPINFO_KEY = process.env.IPINFO_KEY;
const APP_API_KEY = process.env.APP_API_KEY; // optional: protect your API

// Optional middleware to require an app API key
function requireAppKey(req, res, next) {
  if (!APP_API_KEY) return next(); // not enforced if not set
  const key = req.header('x-api-key') || req.query.apikey;
  if (key !== APP_API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Query AbuseIPDB
async function queryAbuseIP(ip) {
  if (!ABUSEIPDB_KEY) return { error: 'No AbuseIPDB key set' };
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  const res = await fetch(url, { headers: { Key: ABUSEIPDB_KEY, Accept: 'application/json' } });
  if (!res.ok) return { error: `AbuseIPDB: ${res.status}` };
  return res.json();
}

// Query VirusTotal IP
async function queryVirusTotalIP(ip) {
  if (!VT_API_KEY) return { error: 'No VirusTotal key set' };
  const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;
  const res = await fetch(url, { headers: { 'x-apikey': VT_API_KEY } });
  if (!res.ok) return { error: `VirusTotal: ${res.status}` };
  return res.json();
}

// Query VirusTotal Domain
async function queryVirusTotalDomain(domain) {
  if (!VT_API_KEY) return { error: 'No VirusTotal key set' };
  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
  const res = await fetch(url, { headers: { 'x-apikey': VT_API_KEY } });
  if (!res.ok) return { error: `VirusTotal: ${res.status}` };
  return res.json();
}

// Query IPinfo
async function queryIPInfo(ip) {
  try {
    const base = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    const url = IPINFO_KEY ? `${base}?token=${IPINFO_KEY}` : base;
    const res = await fetch(url);
    if (!res.ok) return { error: `ipinfo: ${res.status}` };
    return res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// Main lookup endpoint
app.get('/api/lookup', requireAppKey, async (req, res) => {
  try {
    const { ip, domain } = req.query;
    if (!ip && !domain) return res.status(400).json({ error: 'Provide ip or domain' });

    const cacheKey = ip ? `ip:${ip}` : `domain:${domain}`;
    const cached = cache.get(cacheKey);
    if (cached) return res.json({ cached: true, ...cached });

    const out = { query: ip || domain, type: ip ? 'ip' : 'domain', timestamp: new Date().toISOString(), sources: {} };

    if (ip) {
      try { out.rdns = await dns.reverse(ip); } catch { out.rdns = []; }
      out.sources.abuseipdb = await queryAbuseIP(ip);
      out.sources.virustotal = await queryVirusTotalIP(ip);
      out.sources.ipinfo = await queryIPInfo(ip);
    } else {
      try {
        const a = await dns.resolve(domain, 'A').catch(() => []);
        const ns = await dns.resolve(domain, 'NS').catch(() => []);
        const mx = await dns.resolve(domain, 'MX').catch(() => []);
        const txt = await dns.resolve(domain, 'TXT').catch(() => []);
        out.dns = { A: a, NS: ns, MX: mx, TXT: txt };
      } catch (e) { out.dnsError = e.message; }
      try { out.whois = await whois(domain); } catch (e) { out.whoisError = e.message; }
      out.sources.virustotal = await queryVirusTotalDomain(domain);
    }

    cache.set(cacheKey, out);
    res.json(out);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get('/', (req, res) => res.send('SOC Lookup API is running'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));
