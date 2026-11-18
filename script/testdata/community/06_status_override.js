// 06_status_override.js: turns a rate limit answer into a plain "not found".
if ($response.status === 429 || $response.status === 503) {
  $done({
    status: 'HTTP/1.1 404 Not Found',
    headers: Object.assign({}, $response.headers, { 'Retry-After': '0' }),
  });
} else {
  $done({});
}
