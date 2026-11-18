// 10_argument_parsing.js: $argument is "remove=ads,banner&flag=true".
function parseArgs(s) {
  var out = {};
  (s || '').split('&').forEach(function (pair) {
    if (!pair) return;
    var i = pair.indexOf('=');
    var k = decodeURIComponent(i < 0 ? pair : pair.slice(0, i));
    out[k] = i < 0 ? '' : decodeURIComponent(pair.slice(i + 1));
  });
  return out;
}

var args = parseArgs($argument);
var keys = (args.remove || '').split(',').filter(Boolean);
var obj = JSON.parse($response.body);
keys.forEach(function (k) { delete obj[k]; });
if (args.flag === 'true') obj.flagged = true;
$done({ body: JSON.stringify(obj) });
