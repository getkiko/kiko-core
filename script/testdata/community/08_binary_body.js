// 08_binary_body.js: replaces a tracking GIF (1x1) with the same bytes, and flips one byte
// of anything else that starts with the GIF magic.
var bytes = $response.body;
var isGif = bytes.length > 6 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46;
if (isGif) {
  var out = new Uint8Array(bytes.length);
  out.set(bytes);
  out[bytes.length - 1] = 0x3b; // trailer
  out[4] = 0x39; // GIF89a
  $done({ body: out });
} else {
  console.log('not a gif: ' + bytes.length + ' bytes');
  $done({});
}
