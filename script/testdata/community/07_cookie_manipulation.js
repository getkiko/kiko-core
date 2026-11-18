// 07_cookie_manipulation.js: drops Secure and SameSite from cookies and adds a debug cookie.
var h = $response.headers;
var key = Object.keys(h).filter(function (k) { return k.toLowerCase() === 'set-cookie'; })[0];
if (key) {
  var cookies = h[key].split(/,(?=\s*[^;,\s]+=)/);
  cookies = cookies.map(function (c) {
    return c.replace(/;\s*Secure/gi, '').replace(/;\s*SameSite=\w+/gi, '');
  });
  cookies.push('debug=1; Path=/');
  h[key] = cookies.join(', ');
} else {
  h['Set-Cookie'] = 'debug=1; Path=/';
}
$done({ headers: h });
