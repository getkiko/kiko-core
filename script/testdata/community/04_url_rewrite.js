// 04_url_rewrite.js: moves api v1 calls to the v2 host.
var url = $request.url;
if (/^https:\/\/api\.example\.com\/v1\//.test(url)) {
  url = url.replace('https://api.example.com/v1/', 'https://api2.example.com/v2/');
  console.log('rewrite -> ' + url);
}
$done({ url: url });
