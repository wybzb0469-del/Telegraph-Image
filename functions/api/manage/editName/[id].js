import { jsonResponse, parseFileKey } from '../../../utils/security.js';

/**
 * 修改展示用文件名。
 * 前端实际调用的是 ?newName=xxx（旧代码读的是不存在的 params.name，一直是坏的）。
 * 文件名只用于展示，清洗后写入 metadata，长度与字符都受限。
 */
export async function onRequest(context) {
  const { params, env, request } = context;

  if (!env?.img_url) return jsonResponse({ error: '未绑定 KV' }, 400);

  const parsed = parseFileKey(params.id);
  if (!parsed) return jsonResponse({ error: '非法的文件标识' }, 400);

  const url = new URL(request.url);
  const raw = url.searchParams.get('newName') ?? url.searchParams.get('name') ?? '';
  const newName = String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[\\/]/g, '_')
    .trim()
    .slice(0, 120);

  if (!newName) return jsonResponse({ error: '文件名不能为空' }, 400);

  const value = await env.img_url.getWithMetadata(parsed.key);
  if (!value?.metadata) {
    return jsonResponse({ error: `记录不存在: ${parsed.key}` }, 404);
  }

  value.metadata.fileName = newName;
  await env.img_url.put(parsed.key, '', { metadata: value.metadata });

  return jsonResponse({ success: true, fileName: newName });
}
