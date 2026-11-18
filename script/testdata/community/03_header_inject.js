// 03_header_inject.js
const headers = $request.headers;
const ua = headers['User-Agent'] || headers['user-agent'] || '';

if (!/MyApp\//.test(ua)) {
  headers['User-Agent'] = ua + ' MyApp/9.9.9';
}
headers['X-Requested-With'] = 'com.example.app';
headers['Referer'] = 'https://www.example.com/';
delete headers['If-None-Match'];
delete headers['if-none-match'];

$done({ headers });
