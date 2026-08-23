const crypto = require('crypto');

function sha512(value) { return crypto.createHash('sha512').update(value, 'utf8').digest('hex'); }
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || '').toLowerCase());
  const bb = Buffer.from(String(b || '').toLowerCase());
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return Object.fromEntries(new URLSearchParams(req.body));
  return {};
}
function responseHash(p, salt) {
  const udf1=p.udf1||'', udf2=p.udf2||'', udf3=p.udf3||'', udf4=p.udf4||'', udf5=p.udf5||'';
  const base = p.additional_charges
    ? `${p.additional_charges}|${salt}|${p.status}||||||${udf5}|${udf4}|${udf3}|${udf2}|${udf1}|${p.email||''}|${p.firstname||''}|${p.productinfo||''}|${p.amount||''}|${p.txnid||''}|${p.key||''}`
    : `${salt}|${p.status}||||||${udf5}|${udf4}|${udf3}|${udf2}|${udf1}|${p.email||''}|${p.firstname||''}|${p.productinfo||''}|${p.amount||''}|${p.txnid||''}|${p.key||''}`;
  return sha512(base);
}
function tokenFor(txnid, salt, exp) {
  const payload = `${txnid}.${exp}`;
  const sig = sha512(`${payload}|${salt}`);
  return Buffer.from(`${payload}.${sig}`).toString('base64url');
}

async function verifyWithPayU(txnid, key, salt) {
  const var1 = txnid;
  const hash = sha512(`${key}|verify_payment|${var1}|${salt}`);
  const body = new URLSearchParams({key, command:'verify_payment', var1, hash});
  const r = await fetch('https://info.payu.in/merchant/postservice.php?form=2', {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
  if (!r.ok) return false;
  const data = await r.json();
  const detail = data?.transaction_details?.[txnid];
  return data?.status === 1 && detail?.status === 'success' && Number(detail?.amt ?? detail?.transaction_amount) === 7;
}

module.exports = async (req, res) => {
  const p = parseBody(req);
  const key = process.env.PAYU_KEY, salt = process.env.PAYU_SALT;
  if (!key || !salt) return res.status(500).send('Payment server is not configured.');
  if (p.key !== key || p.status !== 'success' || p.amount !== '7.00' || !p.txnid) return res.status(400).send('Payment could not be verified.');
  if (!safeEqual(responseHash(p, salt), p.hash)) return res.status(400).send('Invalid PayU response.');
  try {
    const verified = await verifyWithPayU(p.txnid, key, salt);
    if (!verified) return res.status(400).send('PayU verification failed.');
  } catch (e) {
    console.error('PayU verify error', e);
    return res.status(502).send('Unable to verify payment with PayU.');
  }
  const exp = Math.floor(Date.now()/1000) + 15 * 60;
  const token = tokenFor(p.txnid, salt, exp);
  return res.redirect(303, `https://sahin040703.github.io/?paid=1&token=${encodeURIComponent(token)}`);
};
