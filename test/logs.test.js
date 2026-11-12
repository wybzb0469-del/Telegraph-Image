const assert = require('assert');

/**
 * 审计日志、缩略图通道回归测试。
 */

const ORIGIN = 'https://img.example.com';
const KEY = 'AgACAgFAKEFILEIDxxxxxxxxxxxxxxxxxxxxxxxxxxx.png';

/** 带 metadata 的 KV 模拟：list 需要返回 metadata（日志就是存在 metadata 里的） */
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
    async list({ prefix = '', limit = 1000 } = {}) {
      const names = [...store.keys()].filter((n) => n.startsWith(prefix)).sort();
      return {
        keys: names.slice(0, limit).map((name) => ({ name, metadata: meta.get(name) || null })),
        list_complete: names.length <= limit,
        cursor: undefined,
      };
    },
  };
}

function makeRequest(headers = {}) {
  return new Request(`${ORIGIN}/upload`, {
    method: 'POST',
    headers: {
      'cf-connecting-ip': '203.0.113.7',
      'user-agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
      ...headers,
    },
  });
}

describe('审计日志：写入与读取', function () {
  let log;

  before(async () => {
    log = await import('../functions/utils/audit-log.js');
  });

  it('写入一条日志，元数据包含 IP / UA / 动作', async function () {
    const kv = makeKv();
    const request = makeRequest();
    request.cf = { country: 'JP', city: 'Tokyo', colo: 'NRT', asn: 2516 };

    await log.writeLog({ request, env: { img_url: kv } }, {
      action: 'upload',
      ok: true,
      code: 'OK',
      fileKey: KEY,
      fileName: 'photo.png',
      fileSize: 2048,
      mime: 'image/png',
      durationMs: 123,
    });

    const keys = [...kv.store.keys()];
    assert.strictEqual(keys.length, 1);
    assert.ok(keys[0].startsWith('log:'));

    const entry = kv.meta.get(keys[0]);
    assert.strictEqual(entry.action, 'upload');
    assert.strictEqual(entry.ip, '203.0.113.7');
    assert.strictEqual(entry.country, 'JP');
    assert.ok(/Chrome/.test(entry.ua));
    assert.strictEqual(entry.fileKey, KEY);
    assert.strictEqual(entry.ok, true);
  });

  it('读取按时间从新到旧', async function () {
    const kv = makeKv();
    const env = { img_url: kv };
    const request = makeRequest();

    for (const action of ['upload', 'upload_rejected', 'file_blocked']) {
      await log.writeLog({ request, env }, { action });
      await new Promise((r) => setTimeout(r, 3));
    }

    const result = await log.readLogs(env, { limit: 10 });
    assert.strictEqual(result.enabled, true);
    assert.strictEqual(result.entries.length, 3);
    // 最后写入的应该排在最前
    assert.strictEqual(result.entries[0].action, 'file_blocked');
    assert.strictEqual(result.entries[2].action, 'upload');
  });

  it('LOG_ENABLED=false 时不写日志', async function () {
    const kv = makeKv();
    await log.writeLog({ request: makeRequest(), env: { img_url: kv, LOG_ENABLED: 'false' } }, {
      action: 'upload',
    });
    assert.strictEqual(kv.store.size, 0);
  });

  it('未绑定 KV 时日志降级为关闭，不抛异常', async function () {
    const result = await log.readLogs({}, {});
    assert.strictEqual(result.enabled, false);
    assert.deepStrictEqual(result.entries, []);
  });

  it('清空日志', async function () {
    const kv = makeKv();
    const env = { img_url: kv };
    await log.writeLog({ request: makeRequest(), env }, { action: 'upload' });
    await log.writeLog({ request: makeRequest(), env }, { action: 'upload' });
    const cleared = await log.clearLogs(env, { max: 10 });
    assert.strictEqual(cleared.deleted, 2);
    assert.strictEqual(kv.store.size, 0);
  });
});

describe('上传失败也要留痕', function () {
  let upload;

  before(async () => {
    upload = (await import('../functions/upload.js')).onRequestPost;
  });

  it('非图片上传被拒后写入日志', async function () {
    const kv = makeKv();
    const form = new FormData();
    form.append('file', new File([Buffer.from('<?php echo 1; ?>')], 'shell.php', { type: 'image/png' }));

    const request = new Request(`${ORIGIN}/upload`, {
      method: 'POST',
      body: form,
      headers: { 'cf-connecting-ip': '198.51.100.9', 'user-agent': 'curl/8.4.0' },
    });

    const res = await upload({ request, env: { TG_Bot_Token: '1:a', TG_Chat_ID: '-1', img_url: kv } });
    assert.strictEqual(res.status, 415);

    const logKeys = [...kv.store.keys()].filter((k) => k.startsWith('log:'));
    assert.strictEqual(logKeys.length, 1);
    const entry = kv.meta.get(logKeys[0]);
    assert.strictEqual(entry.action, 'upload_rejected');
    assert.strictEqual(entry.code, 'NOT_IMAGE');
    assert.strictEqual(entry.ip, '198.51.100.9');
    assert.strictEqual(entry.ok, false);
  });
});

describe('缩略图通道', function () {
  let thumb;
  let originalFetch;

  before(async () => {
    thumb = (await import('../functions/thumb/[id].js')).onRequest;
  });

  beforeEach(function () {
    originalFetch = globalThis.fetch;
  });

  afterEach(function () {
    globalThis.fetch = originalFetch;
  });

  function ctx(key, kv, url = `/thumb/${key}`) {
    return {
      request: new Request(`${ORIGIN}${url}`),
      env: { TG_Bot_Token: '1:a', img_url: kv },
      params: { id: key },
    };
  }

  it('老记录没有 thumbFileId 时 302 回落到原图', async function () {
    const kv = makeKv();
    kv.store.set(KEY, '');
    kv.meta.set(KEY, { ListType: 'None', Label: 'None', fileName: 'a.png' });

    const res = await thumb(ctx(KEY, kv));
    assert.strictEqual(res.status, 302);
    assert.ok(res.headers.get('location').endsWith(`/file/${KEY}`));
  });

  it('有 thumbFileId 时返回缩略图并带安全头', async function () {
    const kv = makeKv();
    kv.store.set(KEY, '');
    kv.meta.set(KEY, { ListType: 'None', Label: 'None', fileName: 'a.png', thumbFileId: 'THUMB_ID' });

    globalThis.fetch = async (url) => {
      if (String(url).includes('/getFile')) {
        return new Response(JSON.stringify({ ok: true, result: { file_path: 'photos/thumb.jpg' } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(Buffer.from([0xff, 0xd8, 0xff, 0xd9]), {
        status: 200,
        headers: { 'content-type': 'image/jpeg' },
      });
    };

    const res = await thumb(ctx(KEY, kv));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(/immutable/.test(res.headers.get('cache-control')));
  });

  it('黑名单记录连缩略图也不给', async function () {
    const kv = makeKv();
    kv.store.set(KEY, '');
    kv.meta.set(KEY, { ListType: 'Block', thumbFileId: 'THUMB_ID' });
    const res = await thumb(ctx(KEY, kv));
    assert.strictEqual(res.status, 404);
  });
});
