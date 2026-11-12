/**
 * 后台列表接口。
 *
 * 输出侧清洗：后台页面（admin-imgtc.html）用 v-html 渲染 fileName / name，
 * 而这两个字段都可能被上传者控制。与其在三个页面里逐个转义，
 * 不如在 API 边界统一处理 —— 一处生效，覆盖存量数据。
 */

const UNSAFE_CHARS = /[<>&"']/;

function cleanText(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/[<>&"']/g, '');
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const raw = url.searchParams.get('limit');
  let limit = parseInt(raw || '100', 10);
  if (!Number.isFinite(limit) || limit <= 0) limit = 100;
  if (limit > 1000) limit = 1000;

  const cursor = url.searchParams.get('cursor') || undefined;
  const prefix = url.searchParams.get('prefix') || undefined;
  const value = await env.img_url.list({ limit, cursor, prefix });

  const keys = Array.isArray(value?.keys) ? value.keys : [];
  const safeKeys = [];

  for (const entry of keys) {
    const name = entry?.name;
    // name 同时被当成 key 用来删除/重命名，不能改；含危险字符的直接不返回
    // （这类 key 在 /file 侧本来就会 404，可用 /api/manage/scan 清理）
    if (typeof name !== 'string' || UNSAFE_CHARS.test(name) || /[\u0000-\u001F]/.test(name)) {
      continue;
    }
    if (entry.metadata && typeof entry.metadata === 'object') {
      entry.metadata = { ...entry.metadata, fileName: cleanText(entry.metadata.fileName) };
    }
    safeKeys.push(entry);
  }

  const payload = { ...value, keys: safeKeys };

  return new Response(JSON.stringify(payload), {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
