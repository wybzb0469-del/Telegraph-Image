const assert = require('assert');

/**
 * 后台接口与 CSRF 防护回归测试。
 * 运行：npx mocha test/manage.test.js
 */

const ORIGIN = 'https://img.example.com';
const KEY = 'AgACAgFAKEFILEIDxxxxxxxxxxxxxxxxxxxxxxxxxxx.png';

function makeKv(seed = {}) {
  const store = new Map(Object.entries(seed));
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
      return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true };
    },
  };
}

function seededKv(listType = 'None') {
  const kv = makeKv();
  kv.store.set(KEY, '');
  kv.meta.set(KEY, {
    TimeStamp: Date.now(),
    ListType: listType,
    Label: 'None',
    liked: false,
    fileName: 'photo.png',
    fileSize: 1234,
  });
  return kv;
}

function ctx(path, { method = 'GET', headers = {}, kv } = {}) {
  const request = new Request(`${ORIGIN}${path}`, { method, headers });
  return {
    request,
    env: { img_url: kv || seededKv() },
    params: { id: path.split('/').pop() },
  };
}

describe('后台接口：CSRF 防护', function () {
  let middleware;

  before(async () => {
    middleware = await import('../functions/api/manage/_middleware.js');
  });

  function run(request) {
    const auth = middleware.onRequest[1];
    return auth({ request, env: { img_url: seededKv() }, next: async () => new Response('ok') });
  }

  it('跨站 Origin 被拒绝', async function () {
    const res = await run(
      new Request(`${ORIGIN}/api/manage/list`, { headers: { origin: 'https://evil.example' } })
    );
    assert.strictEqual(res.status, 403);
  });

  it('Sec-Fetch-Site: cross-site 被拒绝', async function () {
    const res = await run(
      new Request(`${ORIGIN}/api/manage/delete/${KEY}`, { headers: { 'sec-fetch-site': 'cross-site' } })
    );
    assert.strictEqual(res.status, 403);
  });

  it('同源请求放行', async function () {
    const res = await run(
      new Request(`${ORIGIN}/api/manage/list`, {
        headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin' },
      })
    );
    assert.strictEqual(await res.text(), 'ok');
  });

  it('无 Origin 的 CLI/curl 调用放行（不破坏脚本化使用）', async function () {
    const res = await run(new Request(`${ORIGIN}/api/manage/list`));
    assert.strictEqual(await res.text(), 'ok');
  });

  it('外站 Referer 也被挡（老浏览器兜底）', async function () {
    const res = await run(
      new Request(`${ORIGIN}/api/manage/list`, { headers: { referer: 'https://evil.example/x' } })
    );
    assert.strictEqual(res.status, 403);
  });
});

describe('后台接口：入参校验与元数据更新', function () {
  let block;
  let white;
  let del;
  let like;

  before(async () => {
    block = (await import('../functions/api/manage/block/[id].js')).onRequest;
    white = (await import('../functions/api/manage/white/[id].js')).onRequest;
    del = (await import('../functions/api/manage/delete/[id].js')).onRequest;
    like = (await import('../functions/api/manage/toggleLike/[id].js')).onRequest;
  });

  it('非法 key 返回 400（旧版会直接操作 KV）', async function () {
    const c = ctx('/api/manage/block/..%2f..%2fetc');
    c.params = { id: '../../etc/passwd' };
    const res = await block(c);
    assert.strictEqual(res.status, 400);
  });

  it('记录不存在返回 404 而不是 500', async function () {
    const c = ctx('/api/manage/block/unknown.png', { kv: makeKv() });
    const res = await block(c);
    assert.strictEqual(res.status, 404);
  });

  it('block 写入 ListType=Block 且保留原字段', async function () {
    const kv = seededKv();
    const res = await block(ctx(`/api/manage/block/${KEY}`, { kv }));
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.ListType, 'Block');
    assert.strictEqual(body.fileName, 'photo.png');
    assert.strictEqual(kv.meta.get(KEY).ListType, 'Block');
  });

  it('white 写入 ListType=White', async function () {
    const kv = seededKv('Block');
    const res = await white(ctx(`/api/manage/white/${KEY}`, { kv }));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(kv.meta.get(KEY).ListType, 'White');
  });

  it('delete 删除对应记录', async function () {
    const kv = seededKv();
    const res = await del(ctx(`/api/manage/delete/${KEY}`, { kv }));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.json().then((d) => d.success), true);
    assert.strictEqual(kv.store.has(KEY), false);
  });

  it('toggleLike 切换收藏状态（保持原响应形状）', async function () {
    const kv = seededKv();
    const first = await like(ctx(`/api/manage/toggleLike/${KEY}`, { kv }));
    assert.deepStrictEqual(await first.json(), { success: true, liked: true });
    const second = await like(ctx(`/api/manage/toggleLike/${KEY}`, { kv }));
    assert.deepStrictEqual(await second.json(), { success: true, liked: false });
  });
});

describe('Bing 壁纸接口', function () {
  let wallpaper;
  let originalFetch;

  before(async () => {
    wallpaper = (await import('../functions/api/bing/wallpaper/index.js')).onRequest;
  });

  beforeEach(function () {
    originalFetch = globalThis.fetch;
  });

  afterEach(function () {
    globalThis.fetch = originalFetch;
  });

  function wctx() {
    return {
      request: new Request('https://img.example.com/api/bing/wallpaper', {
        headers: { 'cf-connecting-ip': `10.1.1.${Math.floor(Math.random() * 200)}` },
      }),
      env: {},
    };
  }

  it('正常返回 images 数组', async function () {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ images: [{ url: '/th?id=1' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const res = await wallpaper(wctx());
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, true);
    assert.strictEqual(body.data.length, 1);
  });

  it('上游失败时降级为空数组而不是 500', async function () {
    globalThis.fetch = async () => {
      throw new Error('network down');
    };
    const res = await wallpaper(wctx());
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, false);
    assert.deepStrictEqual(body.data, []);
  });
});
