// 02_base64_body.js: the interesting part of the payload is base64 encoded JSON.
var raw = JSON.parse($response.body);
function fromB64(s) {
  return decodeURIComponent(escape(atob(s)));
}
function toB64(s) {
  return btoa(unescape(encodeURIComponent(s)));
}
try {
  var inner = JSON.parse(fromB64(raw.payload));
  inner.vip = true;
  inner.expire = 4102444800;
  inner.nick = inner.nick + ' ✓';
  raw.payload = toB64(JSON.stringify(inner));
} catch (e) {
  console.log('payload not decodable: ' + e);
}
$done({ body: JSON.stringify(raw) });
