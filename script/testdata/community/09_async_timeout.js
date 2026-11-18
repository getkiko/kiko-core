// 09_async_timeout.js: waits for a lookup (simulated) before it answers.
function lookup(key) {
  return new Promise(function (resolve) {
    setTimeout(function () { resolve(key.toUpperCase()); }, 40);
  });
}

(async function () {
  var token = await lookup('abc');
  var h = $request.headers;
  h['X-Token'] = token;
  $done({ headers: h });
})();
