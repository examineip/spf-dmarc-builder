'use strict';
// node tests/run.js: address checks are compared against Node's own net module.

const path = require('path');
const assert = require('assert');
const net = require('net');
const b = require(path.join(__dirname, '..', 'spf-dmarc-builder.js'));

let passed = 0;
function t(name, fn) {
  try { fn(); passed++; } catch (e) { console.error('FAIL', name, '\n', e.message); process.exitCode = 1; }
}

t('empty SPF', () => assert.strictEqual(b.buildSpf().record, 'v=spf1 ~all'));
t('domain that sends no mail', () => {
  const r = b.buildSpf({ all: '-' });
  assert.strictEqual(r.record, 'v=spf1 -all');
  assert.deepStrictEqual(r.warnings, []);
});
t('order and duplicates', () => {
  const r = b.buildSpf({ mx: true, a: true, providers: ['google-workspace'], include: ['_spf.google.com', 'include:spf.example.net'], ips: ['192.0.2.1'] });
  assert.strictEqual(r.record, 'v=spf1 a mx include:_spf.google.com include:spf.example.net ip4:192.0.2.1 ~all');
  assert.strictEqual(r.ownLookups, 4);
});
t('IPv6 is lowercased', () => assert.ok(b.buildSpf({ ips: ['2001:DB8::1/64'] }).record.includes('ip6:2001:db8::1/64')));
t('bad values are reported and left out', () => {
  const r = b.buildSpf({ include: ['bad_host!'], ips: ['300.1.1.1', '1:2:3'], providers: ['nope'] });
  assert.strictEqual(r.record, 'v=spf1 ~all');
  assert.strictEqual(r.errors.length, 4);
});
t('invalid all falls back', () => {
  const r = b.buildSpf({ all: '+' });
  assert.strictEqual(r.record, 'v=spf1 ~all');
  assert.ok(r.errors[0].startsWith('invalid-all'));
});
t('over the lookup limit warns', () => {
  const include = Array.from({ length: 11 }, (_, i) => 'a' + i + '.example.net');
  assert.ok(b.buildSpf({ include }).warnings.includes('over-lookup-limit'));
});
t('exactly at the limit does not warn', () => {
  const include = Array.from({ length: 10 }, (_, i) => 'a' + i + '.example.net');
  assert.ok(!b.buildSpf({ include }).warnings.includes('over-lookup-limit'));
});
t('long records split at 255 and rejoin exactly', () => {
  const ips = Array.from({ length: 40 }, (_, i) => '203.0.113.' + (i + 1));
  const r = b.buildSpf({ ips });
  assert.ok(r.strings.length > 1);
  r.strings.forEach((s) => assert.ok(s.length <= 255));
  assert.strictEqual(r.strings.join(''), r.record);
});
t('provider includes are hostnames', () => Object.values(b.PROVIDERS).forEach((h) => assert.ok(b.isHost(h), h)));

t('default DMARC', () => {
  const r = b.buildDmarc();
  assert.strictEqual(r.record, 'v=DMARC1; p=none');
  assert.ok(r.warnings.includes('policy-blocks-nothing'));
  assert.ok(r.warnings.includes('no-report-address'));
});
t('full DMARC', () => {
  const r = b.buildDmarc({ p: 'reject', sp: 'quarantine', rua: ['dmarc@example.com', 'mailto:b@example.org'], adkim: 's', aspf: 's' });
  assert.strictEqual(r.record, 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com,mailto:b@example.org; adkim=s; aspf=s');
  assert.deepStrictEqual(r.errors, []);
});
t('relaxed alignment is left out', () => assert.ok(!b.buildDmarc({ adkim: 'r', aspf: 'r' }).record.includes('adkim')));
t('sp=none under an enforcing policy warns', () => assert.ok(b.buildDmarc({ p: 'reject', sp: 'none' }).warnings.includes('subdomains-left-open')));
t('bad DMARC values', () => {
  const r = b.buildDmarc({ p: 'block', sp: 'x', rua: ['nope'] });
  assert.strictEqual(r.record, 'v=DMARC1; p=none');
  assert.strictEqual(r.errors.length, 3);
});
t('host names', () => { assert.strictEqual(b.buildDmarc().host, '_dmarc'); assert.strictEqual(b.buildSpf().host, '@'); });

const V4 = ['0.0.0.0', '192.0.2.1', '255.255.255.255', '256.1.1.1', '1.2.3', '1.2.3.4.5', '1.2.3.a', '', '999.999.999.999'];
const V6 = ['::', '::1', '2001:db8::1', '2001:0db8:0000:0000:0000:ff00:0042:8329', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7::', '::ffff:192.0.2.1', '64:ff9b::192.0.2.33',
  '1:2:3', ':::', '1::2::3', '12345::', 'g::1', '1:2:3:4:5:6:7:8:9', '::ffff:999.0.2.1', '1:2:3:4:5:6:7', '1.2.3.4'];
V4.forEach((a) => t('ip4 ' + a, () => assert.strictEqual(b.isIp4(a), net.isIPv4(a))));
V6.forEach((a) => t('ip6 ' + a, () => assert.strictEqual(b.isIp6(a), net.isIPv6(a))));

// Pseudo-random addresses, same seed every run.
let seed = 20261108;
function rnd(n) { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; }
for (let i = 0; i < 2000; i++) {
  const groups = Array.from({ length: 8 }, () => rnd(65536).toString(16));
  const full = groups.join(':');
  const cut = rnd(7) + 1;
  const left = groups.slice(0, cut).join(':');
  const right = groups.slice(cut + 1).join(':');
  const zipped = left + '::' + right;
  [full, zipped].forEach((a) => {
    if (b.isIp6(a) !== net.isIPv6(a)) { console.error('FAIL ip6', a); process.exitCode = 1; } else { passed++; }
  });
  const v4 = [rnd(300), rnd(300), rnd(300), rnd(300)].join('.');
  if (b.isIp4(v4) !== net.isIPv4(v4)) { console.error('FAIL ip4', v4); process.exitCode = 1; } else { passed++; }
}

const src = require('fs').readFileSync(path.join(__dirname, '..', 'spf-dmarc-builder.js'), 'utf8');
t('library has no ampersands', () => assert.strictEqual(src.indexOf('&'), -1));

console.log(passed + ' passed' + (process.exitCode ? ', with failures' : ', 0 failed'));
