package script

// preludeSource runs once per VM with a natives object. It builds the parts of the
// environment that are simpler in JavaScript than in Go.
const preludeSource = `(function (n, g) {
  var fmt = function (a) {
    if (typeof a === 'string') return a;
    if (a instanceof Error) return a.stack ? String(a.stack) : String(a);
    if (typeof a === 'function') return String(a);
    try { var s = JSON.stringify(a); return s === undefined ? String(a) : s; } catch (e) { return String(a); }
  };
  var level = function (name) {
    return function () {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) parts.push(fmt(arguments[i]));
      n.log(name, parts.join(' '));
    };
  };
  g.console = { log: level('log'), info: level('info'), warn: level('warn'), error: level('error'), debug: level('log') };
  function TextEncoder() {}
  TextEncoder.prototype.encoding = 'utf-8';
  TextEncoder.prototype.encode = function (s) { return n.encode(s === undefined ? '' : String(s)); };
  function TextDecoder() {}
  TextDecoder.prototype.encoding = 'utf-8';
  TextDecoder.prototype.decode = function (b) { return b === undefined ? '' : n.decode(b); };
  g.TextEncoder = TextEncoder;
  g.TextDecoder = TextDecoder;
  g.atob = n.atob;
  g.btoa = n.btoa;
  g.setTimeout = n.setTimeout;
  g.clearTimeout = n.clearTimeout;
  g.setInterval = n.setInterval;
  g.clearInterval = n.clearInterval;
  g.setImmediate = function (f) { return n.setTimeout(f, 0); };
  var request = function (method) { return function (opts, cb) { n.http(method, opts, cb); }; };
  g.$httpClient = Object.freeze({ get: request('GET'), post: request('POST'), put: request('PUT'), delete: request('DELETE'), head: request('HEAD'), options: request('OPTIONS'), patch: request('PATCH') });
  var nullFn = function () { return null; };
  g.$utils = Object.freeze({ ungzip: function (data) { return n.ungzip(data); }, geoip: nullFn, ipasn: nullFn, ipaso: nullFn });
  // goja's JSON.stringify checks for cycles with a scan per level, so a deep structure takes
  // quadratic time inside native code that no interrupt can stop, and recursion depth is only
  // bounded by the Go stack. Refuse deep values up front.
  var tooDeep = function (v, d) {
    if (d > 400) return true;
    if (v === null || typeof v !== 'object') return false;
    if (Array.isArray(v)) {
      for (var i = 0; i < v.length; i++) { if (tooDeep(v[i], d + 1)) return true; }
      return false;
    }
    for (var k in v) { if (tooDeep(v[k], d + 1)) return true; }
    return false;
  };
  var nativeStringify = JSON.stringify;
  JSON.stringify = function stringify(value, replacer, space) {
    if (value !== null && typeof value === 'object' && tooDeep(value, 0)) throw new TypeError('JSON.stringify: structure is cyclic or nested too deeply');
    return nativeStringify.call(JSON, value, replacer, space);
  };
  var limited = ['Array', 'ArrayBuffer', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array'];
  limited.forEach(function (name) {
    var O = g[name];
    if (typeof O !== 'function') return;
    var W = n.limit(name, O);
    Object.getOwnPropertyNames(O).forEach(function (k) {
      if (k === 'length' || k === 'name' || k === 'prototype') return;
      Object.defineProperty(W, k, Object.getOwnPropertyDescriptor(O, k));
    });
    Object.setPrototypeOf(W, Object.getPrototypeOf(O));
    Object.defineProperty(W, 'prototype', { value: O.prototype });
    Object.defineProperty(O.prototype, 'constructor', { value: W, writable: true, configurable: true });
    Object.defineProperty(g, name, { value: W, writable: true, configurable: true });
  });
  // ---- natives that loop or recurse without any interrupt check ----
  var CAP = n.maxArray;
  var rapply = Reflect.apply;
  var chk = function (x) {
    if (x !== null && (typeof x === 'object' || typeof x === 'function')) {
      var l = x.length;
      if (l > CAP) throw new RangeError('array too large');
    }
  };
  var hide = function (obj, name, value) {
    Object.defineProperty(obj, name, { value: value, writable: true, configurable: true });
  };
  // Methods that walk or copy 'this' for its whole length, however sparse.
  ['map', 'filter', 'forEach', 'reduce', 'reduceRight', 'some', 'every', 'find', 'findIndex', 'findLast', 'findLastIndex',
   'indexOf', 'lastIndexOf', 'includes', 'reverse', 'sort', 'slice', 'splice', 'fill', 'copyWithin', 'keys', 'entries',
   'values', 'at', 'flatMap', 'unshift', 'shift', 'toReversed', 'toSorted', 'toSpliced', 'with'].forEach(function (name) {
    var f = Array.prototype[name];
    if (typeof f !== 'function') return;
    hide(Array.prototype, name, function () { chk(this); return rapply(f, this, arguments); });
  });
  hide(Array.prototype, Symbol.iterator, Array.prototype.values);
  var nativeConcat = Array.prototype.concat;
  hide(Array.prototype, 'concat', function () {
    chk(this);
    for (var i = 0; i < arguments.length; i++) chk(arguments[i]);
    return rapply(nativeConcat, this, arguments);
  });
  var nativeFrom = Array.from;
  hide(Array, 'from', function from(src) { chk(src); return rapply(nativeFrom, this, arguments); });
  limited.forEach(function (name) {
    var W = g[name];
    if (typeof W !== 'function' || typeof W.from !== 'function' || name === 'Array' || name === 'ArrayBuffer') return;
    var f = W.from;
    hide(W, 'from', function from(src) { chk(src); return rapply(f, this, arguments); });
  });
  var nativeApply = Function.prototype.apply;
  hide(Function.prototype, 'apply', function apply(thisArg, args) {
    chk(args);
    return rapply(this, thisArg, args === undefined || args === null ? [] : args);
  });
  hide(Reflect, 'apply', function apply(f, thisArg, args) { chk(args); return rapply(f, thisArg, args); });
  // join, toString, toLocaleString and flat recurse in native code, which a cyclic or deeply
  // nested array turns into a Go stack overflow that kills the process.
  var stack = [];
  var guarded = function (f) {
    return function () {
      chk(this);
      if (stack.length > 100) throw new RangeError('array nested too deeply');
      for (var i = 0; i < stack.length; i++) { if (stack[i] === this) return ''; }
      stack.push(this);
      try { return rapply(f, this, arguments); } finally { stack.pop(); }
    };
  };
  hide(Array.prototype, 'join', guarded(Array.prototype.join));
  hide(Array.prototype, 'toLocaleString', guarded(Array.prototype.toLocaleString));
  var objectToString = Object.prototype.toString;
  hide(Array.prototype, 'toString', function toString() {
    var j = this.join;
    return typeof j === 'function' ? rapply(j, this, []) : rapply(objectToString, this, []);
  });
  var flatten = function (src, depth, out, path) {
    if (path.length > 400) throw new RangeError('array nested too deeply');
    path.push(src);
    var len = src.length;
    for (var i = 0; i < len; i++) {
      if (!(i in src)) continue;
      var e = src[i];
      if (depth > 0 && Array.isArray(e)) {
        for (var k = 0; k < path.length; k++) { if (path[k] === e) throw new TypeError('cyclic array'); }
        flatten(e, depth - 1, out, path);
      } else {
        out.push(e);
      }
    }
    path.pop();
  };
  hide(Array.prototype, 'flat', function flat(depth) {
    chk(this);
    var d = depth === undefined ? 1 : Number(depth);
    if (d !== d) d = 0;
    var out = [];
    flatten(this, d, out, []);
    return out;
  });
  // eval and the Function constructors parse their argument with a recursive parser: cap what
  // they accept. A direct eval becomes an indirect (global) one.
  var nativeEval = g.eval;
  hide(g, 'eval', function eval(x) {
    if (typeof x !== 'string') return x;
    n.checkSource(x);
    return nativeEval(x);
  });
  var wrapConstructor = function (C) {
    var W = function () {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]));
      n.checkSource(parts.join('\n'));
      return Reflect.construct(C, arguments);
    };
    Object.setPrototypeOf(W, Object.getPrototypeOf(C));
    Object.defineProperty(W, 'prototype', { value: C.prototype });
    hide(C.prototype, 'constructor', W);
    return W;
  };
  hide(g, 'Function', wrapConstructor(Function));
  ['(async function(){})', '(function*(){})', '(async function*(){})'].forEach(function (src) {
    try { wrapConstructor(Object.getPrototypeOf(nativeEval(src)).constructor); } catch (e) {}
  });
  return function () { return Object.getOwnPropertyNames(g); };
})`

// fingerprintSource builds the tamper check: run once after the environment is complete, it
// returns a function that tells whether a call left the shared built-ins as they were.
const fingerprintSource = `(function (g) {
  var targets = [g, Object.prototype, Function.prototype, Array.prototype, String.prototype, Number.prototype,
    Boolean.prototype, Date.prototype, RegExp.prototype, Promise.prototype, Error.prototype, JSON, Math, Reflect,
    Object, Array, String, Promise, Function, Date, RegExp];
  var names = Object.getOwnPropertyNames, extensible = Object.isExtensible, frozen = Object.isFrozen;
  var critical = [JSON.parse, JSON.stringify, Array.prototype.push, Array.prototype.join, Array.prototype.map,
    Array.prototype.slice, Object.keys, Object.defineProperty, String.prototype.split, String.prototype.replace,
    Function.prototype.apply, Function.prototype.call, Object.prototype.hasOwnProperty, Object.prototype.toString,
    g.eval, g.Function, g.setTimeout, g.console, g.$done, g.$persistentStore, g.$notification];
  var read = function () {
    // A number: the count of own properties of every target, with a bit for each one that is
    // no longer extensible or is frozen.
    var sum = 0;
    for (var i = 0; i < targets.length; i++) {
      var t = targets[i];
      sum = sum * 31 + names(t).length;
      if (!extensible(t)) sum += 1000003 * (i + 1);
      if (frozen(t)) sum += 7919 * (i + 1);
      sum = sum % 2147483629;
    }
    return sum;
  };
  var base = read();
  return function () {
    if (read() !== base) return false;
    return critical[0] === JSON.parse && critical[1] === JSON.stringify && critical[2] === Array.prototype.push &&
      critical[3] === Array.prototype.join && critical[4] === Array.prototype.map && critical[5] === Array.prototype.slice &&
      critical[6] === Object.keys && critical[7] === Object.defineProperty && critical[8] === String.prototype.split &&
      critical[9] === String.prototype.replace && critical[10] === Function.prototype.apply &&
      critical[11] === Function.prototype.call && critical[12] === Object.prototype.hasOwnProperty &&
      critical[13] === Object.prototype.toString && critical[14] === g.eval && critical[15] === g.Function &&
      critical[16] === g.setTimeout && critical[17] === g.console && critical[18] === g.$done &&
      critical[19] === g.$persistentStore && critical[20] === g.$notification;
  };
})`
