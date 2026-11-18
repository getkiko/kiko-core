/*
 * 01_json_remove_ads.js
 * Removes advertisement entries from a feed response.
 */
let body = JSON.parse($response.body);

if (body && body.data) {
  if (Array.isArray(body.data.items)) {
    body.data.items = body.data.items.filter(function (item) {
      return !(item.is_ad || item.card_type === 'ad' || (item.tags && item.tags.indexOf('sponsored') !== -1));
    });
  }
  delete body.data.ad_config;
  body.data.total = body.data.items ? body.data.items.length : 0;
}

$done({ body: JSON.stringify(body) });
