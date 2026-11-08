// spf-dmarc-builder: builds SPF and DMARC TXT records and says what is wrong with them.
(function (root, factory) {
  if (typeof module === 'object' ? module.exports : false) {
    module.exports = factory();
  } else {
    root.spfDmarcBuilder = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SPF_LOOKUP_LIMIT = 10;
  var TXT_STRING_LIMIT = 255;

  var PROVIDERS = {
    'google-workspace': '_spf.google.com',
    'microsoft-365': 'spf.protection.outlook.com',
    'hostinger': '_spf.mail.hostinger.com',
    'zoho': 'zohomail.com',
    'proton': '_spf.protonmail.ch',
    'fastmail': 'spf.messagingengine.com',
    'amazon-ses': 'amazonses.com',
    'mailgun': 'mailgun.org',
    'sendgrid': 'sendgrid.net',
    'brevo': 'spf.brevo.com',
    'mailchimp': 'servers.mcsv.net'
  };

  function isHost(s) {
    return /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(String(s));
  }

  function isEmail(s) {
    s = String(s);
    var at = s.lastIndexOf('@');
    if (at < 1) { return false; }
    if (/\s/.test(s)) { return false; }
    return isHost(s.slice(at + 1));
  }

  function isIp4(s) {
    var m = String(s).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
    if (!m) { return false; }
    for (var i = 1; i < 5; i++) {
      if (Number(m[i]) > 255) { return false; }
    }
    if (m[5] !== undefined) {
      if (Number(m[5]) > 32) { return false; }
    }
    return true;
  }

  function isIp6(s) {
    var parts = String(s).split('/');
    if (parts.length > 2) { return false; }
    if (parts.length === 2) {
      if (!/^\d{1,3}$/.test(parts[1])) { return false; }
      if (Number(parts[1]) > 128) { return false; }
    }
    var a = parts[0];
    if (a.indexOf(':') === -1) { return false; }
    if (!/^[0-9a-f:.]+$/i.test(a)) { return false; }
    if (/:::/.test(a)) { return false; }
    var dbl = a.split('::');
    if (dbl.length > 2) { return false; }
    function groups(x) { return x === '' ? [] : x.split(':'); }
    var g = groups(dbl[0]).concat(dbl.length === 2 ? groups(dbl[1]) : []);
    var count = 0;
    for (var i = 0; i < g.length; i++) {
      if (g[i].indexOf('.') !== -1) {
        if (i !== g.length - 1) { return false; }
        if (!isIp4(g[i])) { return false; }
        if (g[i].indexOf('/') !== -1) { return false; }
        count += 2;
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(g[i])) { return false; }
        count += 1;
      }
    }
    if (dbl.length === 2) { return count < 8; }
    return count === 8;
  }

  // TXT strings hold 255 characters at most, so long records are split.
  function toTxtStrings(record) {
    var out = [];
    for (var i = 0; i < record.length; i += TXT_STRING_LIMIT) {
      out.push(record.slice(i, i + TXT_STRING_LIMIT));
    }
    return out;
  }

  function buildSpf(o) {
    o = o || {};
    var terms = [];
    var seen = {};
    var errors = [];
    var warnings = [];
    var lookups = 0;

    function add(term) {
      var k = term.toLowerCase();
      if (seen[k]) { return false; }
      seen[k] = true;
      terms.push(term);
      return true;
    }

    if (o.a) { if (add('a')) { lookups++; } }
    if (o.mx) { if (add('mx')) { lookups++; } }

    (o.providers || []).forEach(function (p) {
      if (Object.prototype.hasOwnProperty.call(PROVIDERS, p)) {
        if (add('include:' + PROVIDERS[p])) { lookups++; }
      } else {
        errors.push('unknown-provider:' + p);
      }
    });
    (o.include || []).forEach(function (h) {
      h = String(h).replace(/^include:/i, '');
      if (isHost(h)) {
        if (add('include:' + h)) { lookups++; }
      } else {
        errors.push('invalid-include:' + h);
      }
    });
    (o.ips || []).forEach(function (ip) {
      var v = String(ip).replace(/^ip[46]:/i, '');
      if (isIp4(v)) {
        add('ip4:' + v);
      } else if (isIp6(v)) {
        add('ip6:' + v.toLowerCase());
      } else {
        errors.push('invalid-ip:' + ip);
      }
    });

    var all = o.all === undefined ? '~' : o.all;
    if (['-', '~', '?'].indexOf(all) === -1) {
      errors.push('invalid-all:' + all);
      all = '~';
    }
    if (all === '?') { warnings.push('neutral-all-gives-little-protection'); }
    if (terms.length === 0) {
      if (all !== '-') { warnings.push('no-senders-listed'); }
    }
    if (lookups > SPF_LOOKUP_LIMIT) { warnings.push('over-lookup-limit'); }

    var record = 'v=spf1 ' + (terms.length ? terms.join(' ') + ' ' : '') + all + 'all';
    return {
      host: '@',
      record: record,
      strings: toTxtStrings(record),
      ownLookups: lookups,
      errors: errors,
      warnings: warnings
    };
  }

  function buildDmarc(o) {
    o = o || {};
    var errors = [];
    var warnings = [];
    var POLICIES = ['none', 'quarantine', 'reject'];

    var p = o.p === undefined ? 'none' : o.p;
    if (POLICIES.indexOf(p) === -1) {
      errors.push('invalid-policy:' + p);
      p = 'none';
    }
    var record = 'v=DMARC1; p=' + p;

    if (o.sp !== undefined) {
      if (POLICIES.indexOf(o.sp) === -1) {
        errors.push('invalid-subdomain-policy:' + o.sp);
      } else {
        record += '; sp=' + o.sp;
        if (o.sp === 'none') {
          if (p !== 'none') { warnings.push('subdomains-left-open'); }
        }
      }
    }

    var good = [];
    (o.rua || []).forEach(function (a) {
      var m = String(a).replace(/^mailto:/i, '');
      if (isEmail(m)) {
        good.push('mailto:' + m);
      } else {
        errors.push('invalid-report-address:' + a);
      }
    });
    if (good.length) {
      record += '; rua=' + good.join(',');
    } else {
      warnings.push('no-report-address');
    }

    if (o.adkim === 's') { record += '; adkim=s'; }
    if (o.aspf === 's') { record += '; aspf=s'; }
    if (p === 'none') { warnings.push('policy-blocks-nothing'); }

    return { host: '_dmarc', record: record, errors: errors, warnings: warnings };
  }

  return {
    buildSpf: buildSpf,
    buildDmarc: buildDmarc,
    toTxtStrings: toTxtStrings,
    isHost: isHost,
    isEmail: isEmail,
    isIp4: isIp4,
    isIp6: isIp6,
    PROVIDERS: PROVIDERS,
    SPF_LOOKUP_LIMIT: SPF_LOOKUP_LIMIT
  };
});
