import { jsonResponse, parseFileKey } from '../../../utils/security.js';

/**
 * 删除 KV 记录（不等于删除 Telegram 上的原图）。
 * 旧版直接用 params.id 调 KV delete，等于允许删任意 key；
 * 这里强制 key 必须是 <fileId>[.<ext>] 形状。
 */
export async function onRequest(context) {
  const { params, env } = context;

  const parsed = parseFileKey(params?.id);
  if (!parsed) return jsonResponse({ error: '非法的文件标识' }, 400);
  if (!env?.img_url) return jsonResponse({ error: '未绑定 KV' }, 400);

  await env.img_url.delete(parsed.key);

  return jsonResponse({ success: true, key: parsed.key });
}
