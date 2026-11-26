module.exports = async function (context, Request) {
  const rawDomain = (Request.query.domain || (Request.body && Request.body.domain) || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0];

  const domainRegex = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/;
  if (!domainRegex.test(rawDomain)) {
    context.res = {
      status: 400,
      headers: { "Content-Type": "application/json" },
      body: { error: "Invalid or missing domain parameter. Example: ?domain=scotiabank.com" }
    };
    return;
  }

  const dohHeaders = { Accept: "application/dns-json" };

  async function fetchJson(url, options = {}) {
    try {
      const res = await fetch(url, { ...options, signal: AbortSignal.timeout(5000) });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  const [oidcData, txtData, dmarcData, mxData] = await Promise.all([
    fetchJson(`https://login.microsoftonline.com/${rawDomain}/v2.0/.well-known/openid-configuration`),
    fetchJson(`https://cloudflare-dns.com/dns-query?name=${rawDomain}&type=TXT`, { headers: dohHeaders }),
    fetchJson(`https://cloudflare-dns.com/dns-query?name=_dmarc.${rawDomain}&type=TXT`, { headers: dohHeaders }),
    fetchJson(`https://cloudflare-dns.com/dns-query?name=${rawDomain}&type=MX`, { headers: dohHeaders })
  ]);

  // 1. Microsoft Entra ID Tenant & Federation Check
  let entraStatus = "Not Detected";
  let tenantId = null;
  if (oidcData && oidcData.issuer) {
    entraStatus = "Entra ID Tenant Active";
    const match = oidcData.issuer.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i);
    if (match) tenantId = match[1];
  }

  // 2. SPF Record Check
  const txtAnswers = (txtData && txtData.Answer) || [];
  const spfEntry = txtAnswers.find((a) => a.data && a.data.toLowerCase().includes("v=spf1"));
  const spfRecord = spfEntry ? spfEntry.data.replace(/^"|"$/g, "") : null;

  // 3. DMARC Policy Check
  const dmarcAnswers = (dmarcData && dmarcData.Answer) || [];
  const dmarcEntry = dmarcAnswers.find((a) => a.data && a.data.toLowerCase().includes("v=dmarc1"));
  const dmarcRecord = dmarcEntry ? dmarcEntry.data.replace(/^"|"$/g, "") : null;
  let dmarcPolicy = "Missing";
  if (dmarcRecord) {
    const pMatch = dmarcRecord.match(/;\s*p=([a-z]+)/i) || dmarcRecord.match(/\bp=([a-z]+)/i);
    dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : "Configured";
  }

  // 4. MX Mail Servers
  const mxServers = ((mxData && mxData.Answer) || [])
    .map((a) => a.data)
    .filter(Boolean);

  // 5. Zero-Trust Perimeter Score (0 - 100)
  let score = 0;
  if (entraStatus !== "Not Detected") score += 30;
  if (spfRecord) score += 30;
  if (dmarcPolicy === "reject") score += 40;
  else if (dmarcPolicy === "quarantine") score += 30;
  else if (dmarcPolicy === "none") score += 15;

  context.res = {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: {
      domain: rawDomain,
      timestampUtc: new Date().toISOString(),
      postureScore: score,
      entraId: {
        status: entraStatus,
        tenantId: tenantId
      },
      emailSecurity: {
        mx: mxServers,
        spf: spfRecord || "Missing",
        dmarcPolicy: dmarcPolicy,
        dmarcRecord: dmarcRecord || "Missing"
      }
    }
  };
};