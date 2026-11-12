const assert = require('assert');

/**
 * 安全回归测试：守住"只能传图片"这条线。
 * 运行：npx mocha
 */

const PNG_BYTES = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000100' +
    '0505050d0a2db40000000049454e44ae426082',
  'hex'
);
const JPEG_BYTES = Buffer.from('ffd8ffe000104a46494600010100000100010000ffd9', 'hex');
const GIF_BYTES = Buffer.concat([
  Buffer.from('GIF89a', 'binary'),
  Buffer.from([0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
]);
const WEBP_BYTES = Buffer.concat([
  Buffer.from('RIFF'),
  Buffer.from([0x1a, 0x00, 0x00, 0x00]),
  Buffer.from('WEBPVP8 '),
]);
const PHP_BYTES = Buffer.from('<?php system($_GET["c"]); ?>', 'utf8');
const HTML_BYTES = Buffer.from('<!DOCTYPE html><script>alert(1)</script>', 'utf8');
const SVG_BYTES = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'utf8');

function makeKv() {
  const store = new Map();
  const meta = new Map();
  return {
    store,
    meta,
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value, options) {
      store.set(key, value);
      if (options && options.metadata) meta.set(key, options.metadata);
    },
    async delete(key) {
      store.delete(key);
      meta.delete(key);
    },
    async getWithMetadata(key) {
      return { value: store.has(key) ? store.get(key) : null, metadata: meta.get(key) || null };
    },
    async list() {
      return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true, cursor: undefined };
    },
  };
}

function makeUploadRequest(fileName, bytes, declaredType, ip) {
  const form = new FormData();
  form.append('file', new File([bytes], fileName, { type: declaredType }));
  return new Request('https://img.example.com/upload', {
    method: 'POST',
    body: form,
    headers: { 'cf-connecting-ip': ip },
  });
}

describe('utils/security: 魔数识别与 key 校验', function () {
  let security;

  before(async () => {
    security = await import('../functions/utils/security.js');
  });

  it('能识别常见图片格式', function () {
    assert.strictEqual(security.sniffImageMime(new Uint8Array(PNG_BYTES)), 'image/png');
    assert.strictEqual(security.sniffImageMime(new Uint8Array(JPEG_BYTES)), 'image/jpeg');
    assert.strictEqual(security.sniffImageMime(new Uint8Array(GIF_BYTES)), 'image/gif');
    assert.strictEqual(security.sniffImageMime(new Uint8Array(WEBP_BYTES)), 'image/webp');
  });

  it('拒绝脚本 / 网页 / SVG 内容', function () {
    assert.strictEqual(security.sniffImageMime(new Uint8Array(PHP_BYTES)), null);
    assert.strictEqual(security.sniffImageMime(new Uint8Array(HTML_BYTES)), null);
    assert.strictEqual(security.sniffImageMime(new Uint8Array(SVG_BYTES)), null);
  });

  it('只允许图片扩展名', function () {
    for (const ext of ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'avif']) {
      assert.ok(security.isAllowedExt(ext), ext);
    }
    for (const ext of ['php', 'phtml', 'asp', 'aspx', 'jsp', 'html', 'htm', 'js', 'svg', 'ico', 'exe', 'sh']) {
      assert.ok(!security.isAllowedExt(ext), ext);
    }
  });

  it('parseFileKey 挡住路径穿越与奇怪字符', function () {
    assert.ok(security.parseFileKey('AgACAgEAAxkDAAMD.png'));
    assert.strictEqual(security.parseFileKey('../../etc/passwd'), null);
    assert.strictEqual(security.parseFileKey('abc%2f..%2f.png'), null);
    assert.strictEqual(security.parseFileKey('a'.repeat(300)), null);
    assert.strictEqual(security.parseFileKey(''), null);
  });

  it('sanitizeFileName 清洗危险字符并强制扩展名', function () {
    assert.strictEqual(security.sanitizeFileName('../../evil.php', 'png'), 'evil.png');
    assert.strictEqual(security.sanitizeFileName('a\u0000b<script>.php', 'jpg'), 'ab_script_.jpg');
    assert.strictEqual(security.sanitizeFileName('', 'gif'), 'image.gif');
    assert.strictEqual(security.sanitizeFileName('中文 名字.png', 'png'), '中文 名字.png');
  });
});

describe('POST /upload: 只接受图片', function () {
  let upload;
  let rate;
  let originalFetch;

  before(async () => {
    upload = await import('../functions/upload.js');
    rate = await import('../functions/utils/rate-limit.js');
  });

  beforeEach(function () {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ ok: true, result: { photo: [{ file_id: 'AgACAgFAKEFILEIDxxxxxxxxxxxxxxxxxxxxxxxxxxx', file_size: 10 }] } }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
  });

  afterEach(function () {
    globalThis.fetch = originalFetch;
  });

  function ctx(request, extraEnv = {}) {
    return {
      request,
      env: {
        TG_Bot_Token: '123:FAKE',
        TG_Chat_ID: '-100123',
        img_url: makeKv(),
        ...extraEnv,
      },
    };
  }

  it('正常 PNG 上传成功，且返回规范扩展名', async function () {
    const res = await upload.onRequestPost(ctx(makeUploadRequest('photo.png', PNG_BYTES, 'image/png', '10.0.0.1')));
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body[0].src.startsWith('/file/'));
    assert.ok(body[0].src.endsWith('.png'), body[0].src);
  });

  it('伪装成 image/png 的 PHP 被拒绝（核心修复）', async function () {
    const res = await upload.onRequestPost(ctx(makeUploadRequest('shell.php', PHP_BYTES, 'image/png', '10.0.0.2')));
    assert.strictEqual(res.status, 415);
    const body = await res.json();
    assert.ok(/仅允许上传图片/.test(body.error), JSON.stringify(body));
  });

  it('HTML 马被拒绝', async function () {
    const res = await upload.onRequestPost(ctx(makeUploadRequest('x.html', HTML_BYTES, 'image/png', '10.0.0.3')));
    assert.strictEqual(res.status, 415);
  });

  it('SVG（可执行脚本）被拒绝', async function () {
    const res = await upload.onRequestPost(ctx(makeUploadRequest('x.svg', SVG_BYTES, 'image/svg+xml', '10.0.0.4')));
    assert.strictEqual(res.status, 415);
  });

  it('扩展名由内容决定：真图片改名 .php 仍按 png 存储', async function () {
    const res = await upload.onRequestPost(ctx(makeUploadRequest('shell.php', PNG_BYTES, 'application/x-php', '10.0.0.5')));
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body[0].src.endsWith('.png'), body[0].src);
  });

  it('超大文件返回 413', async function () {
    const big = Buffer.concat([PNG_BYTES, Buffer.alloc(2048)]);
    const res = await upload.onRequestPost(
      ctx(makeUploadRequest('big.png', big, 'image/png', '10.0.0.6'), { MAX_UPLOAD_SIZE: '1024' })
    );
    assert.strictEqual(res.status, 413);
  });

  it('超过限流阈值返回 429', async function () {
    rate.__resetRateLimitStore();
    const ip = '10.9.9.9';
    let last;
    for (let i = 0; i < 12; i += 1) {
      last = await upload.onRequestPost(ctx(makeUploadRequest('a.png', PNG_BYTES, 'image/png', ip)));
      if (last.status === 429) break;
    }
    assert.strictEqual(last.status, 429);
    assert.ok(last.headers.get('retry-after'));
  });
});

describe('GET /file/:id: 只代理图片', function () {
  let fileHandler;
  let originalFetch;
  let captured;

  before(async () => {
    fileHandler = await import('../functions/file/[id].js');
  });

  beforeEach(function () {
    captured = null;
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      captured = { url: String(url), init };
      return new Response(PNG_BYTES, {
        status: 200,
        headers: { 'content-type': 'image/png', 'content-length': String(PNG_BYTES.length) },
      });
    };
  });

  afterEach(function () {
    globalThis.fetch = originalFetch;
  });

  function ctx(path, headers = {}) {
    const request = new Request(`https://img.example.com${path}`, { headers });
    return {
      request,
      env: { TG_Bot_Token: '123:FAKE' },
      params: { id: path.replace('/file/', '') },
    };
  }

  it('.php 路径直接 404，不再回源', async function () {
    const res = await fileHandler.onRequest(ctx('/file/AgACAgFAKEID.php'));
    assert.strictEqual(res.status, 404);
    assert.strictEqual(captured, null);
  });

  it('.html / .svg / .js 同样被拦', async function () {
    for (const ext of ['html', 'svg', 'js', 'asp']) {
      const res = await fileHandler.onRequest(ctx(`/file/AgACAgFAKEID.${ext}`));
      assert.strictEqual(res.status, 404, ext);
    }
  });

  it('正常图片透出并强制安全响应头', async function () {
    const res = await fileHandler.onRequest(ctx('/file/AgACAgFAKEID.png'));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'image/png');
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(/sandbox/.test(res.headers.get('content-security-policy') || ''));
  });

  it('不把 Authorization / Cookie 转发给上游', async function () {
    await fileHandler.onRequest(
      ctx('/file/AgACAgFAKEID.png', {
        Authorization: 'Basic YWRtaW46c2VjcmV0',
        Cookie: 'session=abc',
      })
    );
    const headers = captured.init.headers;
    const auth = headers instanceof Headers ? headers.get('authorization') : headers && headers.authorization;
    const cookie = headers instanceof Headers ? headers.get('cookie') : headers && headers.cookie;
    assert.strictEqual(auth, null);
    assert.strictEqual(cookie, null);
  });

  it('上游谎报 content-type 时仍按扩展名输出', async function () {
    globalThis.fetch = async () =>
      new Response('<script>alert(1)</script>', { status: 200, headers: { 'content-type': 'text/html' } });
    const res = await fileHandler.onRequest(ctx('/file/AgACAgFAKEID.png'));
    assert.strictEqual(res.headers.get('content-type'), 'image/png');
  });
});
