// 05_mock_response.js: answers the request without asking the server.
const body = {
  code: 0,
  message: 'ok',
  data: { vip: true, level: 9, url: $request.url },
};

$done({
  response: {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
    body: JSON.stringify(body),
  },
});
