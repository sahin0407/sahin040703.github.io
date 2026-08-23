const crypto = require('crypto');

function sha512(value) { return crypto.createHash('sha512').update(value, 'utf8').digest('hex'); }
function safeEqual(a,b){const aa=Buffer.from(String(a||''));const bb=Buffer.from(String(b||''));return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)}

module.exports = async (req,res)=>{
  const token = req.query?.token;
  const salt = process.env.PAYU_SALT;
  if(!token || !salt) return res.status(400).json({ok:false});
  try{
    const raw=Buffer.from(token,'base64url').toString('utf8');
    const parts=raw.split('.');
    if(parts.length!==3) throw new Error('bad token');
    const [txnid,exp,sig]=parts;
    if(Number(exp)<Math.floor(Date.now()/1000)) throw new Error('expired');
    if(!safeEqual(sha512(`${txnid}.${exp}|${salt}`),sig)) throw new Error('bad signature');
    return res.status(200).json({ok:true,message:'R u a Gay? 😂'});
  }catch(e){return res.status(403).json({ok:false});}
};
