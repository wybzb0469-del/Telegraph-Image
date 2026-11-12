import { jsonResponse, parseFileKey } from '../../../utils/security.js';

/** 切换收藏状态。保持原有响应形状 { success, liked }，前端做了乐观更新。 */
export async function onRequest(context) {
  const { params, env } = context;

  const parsed = parseFileKey(params?.id);
  if (!parsed) return jsonResponse({ error: '非法的文件标识' }, 400);
  if (!env?.img_url) return jsonResponse({ error: '未绑定 KV' }, 400);

  const record = await env.img_url.getWithMetadata(parsed.key);
  if (!record?.metadata) {
    return jsonResponse({ error: `记录不存在: ${parsed.key}` }, 404);
  }

  const metadata = { ...record.metadata, liked: !record.metadata.liked };
  await env.img_url.put(parsed.key, '', { metadata });

  return jsonResponse({ success: true, liked: metadata.liked });
}
