# spf-dmarc-builder

Builds SPF and DMARC TXT records, and tells you what's wrong with them before you publish.

One file, no dependencies. Works in Node 18+ and the browser. It's the logic behind the
[SPF and DMARC Record Generator](https://tools.examineip.com/spf-dmarc-generator/).

```js
const { buildSpf, buildDmarc } = require('./spf-dmarc-builder.js');

buildSpf({ mx: true, providers: ['google-workspace'], ips: ['192.0.2.1'], all: '-' }).record;
// 'v=spf1 mx include:_spf.google.com ip4:192.0.2.1 -all'

buildDmarc({ p: 'reject', rua: ['dmarc@example.com'] }).record;
// 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
```

## What it handles

- **Duplicates.** A provider and a hand-typed include for the same host become one term.
- **Bad input.** Invalid hosts, IPs and addresses are reported in `errors` and left out, so a typo can't publish a broken record.
- **The 255-character limit.** A DNS TXT string holds 255 characters, so `strings` gives long SPF records already split.
- **Plain warnings.** `over-lookup-limit`, `no-senders-listed`, `policy-blocks-nothing`, `no-report-address`, `subdomains-left-open` and others.

## What it can't do

- It can't count your real SPF lookups. `ownLookups` covers only the terms in this record, and each include can use more of its own. Use [dmarc-check](https://github.com/examineip/dmarc-check) on the published record for the true total.
- It can't create DKIM. Those keys come from whichever service sends your mail.
- It can't know your senders. Leave one out and its mail may start failing, so start DMARC at `p=none` and read the reports.

## Tests

```
node tests/run.js
```

IP validation is compared against Node's own `net` module on fixed cases and on 6,000 generated addresses.

## License

MIT
