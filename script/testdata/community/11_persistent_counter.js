// 11_persistent_counter.js: counts calls in the persistent store and notifies at the 3rd.
var key = 'counter';
var n = parseInt($persistentStore.read(key) || '0', 10) + 1;
$persistentStore.write(String(n), key);
if (n === 3) {
  $notification.post('Counter', 'reached', 'three calls seen', { url: 'https://example.com/counter' });
}
$done({});
