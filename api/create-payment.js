const crypto = require('crypto');

const API_ORIGIN = process.env.APP_BASE_URL || 'https://prankpage-kappa.vercel.app';
const PAYMENT_URL = process.env.PAYU_TEST_MODE === 'true'
  ? 'https://test.payu.in/_payment'
  : 'https://secure.payu.in/_payment';

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function sha512(value) {
  return crypto.createHash('sha512').update(value, 'utf8').digest('hex');
}

function paymentHash(p, salt) {
  const udf1 = p.udf1 || '', udf2 = p.udf2 || '', udf3 = p.udf3 || '', udf4 = p.udf4 || '', udf5 = p.udf5 || '';
  return sha512(`${p.key}|${p.txnid}|${p.amount}|${p.productinfo}|${p.firstname}|${p.email}|${udf1}|${udf2}|${udf3}|${udf4}|${udf5}||||||${salt}`);
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Method not allowed' });

  const key = process.env.PAYU_KEY;
  const salt = process.env.PAYU_SALT;
  if (!key || !salt) {
    return res.status(500).json({ ok: false, message: 'PayU credentials are not configured on the server.' });
  }

  const txnid = `rt${Date.now().toString(36)}${crypto.randomBytes(3).toString('hex')}`.slice(0, 25);
  const p = {
    key,
    txnid,
    amount: '7.00',
    productinfo: 'RATATAA Secret Message',
    firstname: 'RATATAA Guest',
    email: 'guest@example.com',
    phone: '9999999999',
    udf1: '', udf2: '', udf3: '', udf4: '', udf5: '',
    surl: `${API_ORIGIN}/api/payu/success`,
    furl: `${API_ORIGIN}/api/payu/failure`,
  };
  p.hash = paymentHash(p, salt);

  return res.status(200).json({ ok: true, paymentUrl: PAYMENT_URL, formData: p });
};
