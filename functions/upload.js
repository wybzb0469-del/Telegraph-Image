import {
  ALLOWED_FORMATS_LABEL,
  DEFAULT_MAX_UPLOAD_BYTES,
  HARD_MAX_UPLOAD_BYTES,
  canonicalExtForMime,
  jsonResponse,
  sanitizeFileName,
  sniffImageMime,
} from './utils/security.js';
import { enforceRateLimit, uploadRateRules } from './utils/rate-limit.js';

/**
 * 图片上传接口。
 *
 * 安全约束（与旧版的关键差异）：
 *  1. 先限流，再解析 body —— 超限请求不消耗内存；
 *  2. 文件类型只认文件头魔数，不认客户端 Content-Type；
 *  3. 扩展名由魔数推导，用户文件名只保留展示用主名，不参与路径/存储；
 *  4. 只有图片，没有 sendDocument 的"任意文件"后门（文档降级仅在图片已通过校验时使用）；
 *  5. 大小上限受 Content-Length 与实测 size 双重约束。
 */

function maxUploadBytes(env) {
  const configured = Number(env?.MAX_UPLOAD_SIZE);
  if (Number.isFinite(configured) && configured > 0) {
    return Math.min(Math.floor(configured), HARD_MAX_UPLOAD_BYTES);
  }
  return DEFAULT_MAX_UPLOAD_BYTES;
}

function tooLargeResponse(maxBytes) {
  const mb = (maxBytes / 1024 / 1024).toFixed(1).replace(/\.0$/, '');
  return jsonResponse({ error: `文件过大，最大支持 ${mb} MB` }, 413);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1) 限流：放在最前面，挡掉刷接口的请求
  const limited = await enforceRateLimit(context, {
    scope: 'upload',
    rules: uploadRateRules(env),
    kv: env?.RATE_LIMIT_KV || null,
  });
  if (limited) return limited;

  if (!env?.TG_Bot_Token || !env?.TG_Chat_ID) {
    console.error('upload: TG_Bot_Token / TG_Chat_ID 未配置');
    return jsonResponse({ error: '服务端未配置上传凭据' }, 500);
  }

  const maxBytes = maxUploadBytes(env);

  // 2) 先看声明大小，避免把超大 body 读进内存
  const declaredLength = Number(request.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes + 64 * 1024) {
    return tooLargeResponse(maxBytes);
  }

  let formData;
  try {
    formData = await request.formData();
  } catch (error) {
    return jsonResponse({ error: '请求体解析失败，请使用 multipart/form-data 上传' }, 400);
  }

  const uploadFile = formData.get('file');
  if (!uploadFile || typeof uploadFile === 'string' || typeof uploadFile.arrayBuffer !== 'function') {
    return jsonResponse({ error: '未找到上传文件' }, 400);
  }
  if (!uploadFile.size) {
    return jsonResponse({ error: '文件内容为空' }, 400);
  }
  if (uploadFile.size > maxBytes) {
    return tooLargeResponse(maxBytes);
  }

  // 3) 魔数校验：唯一的类型判定依据
  let head;
  try {
    head = new Uint8Array(await uploadFile.slice(0, 64).arrayBuffer());
  } catch (error) {
    return jsonResponse({ error: '无法读取文件内容' }, 400);
  }

  const mime = sniffImageMime(head);
  if (!mime) {
    return jsonResponse(
      { error: `仅允许上传图片文件（${ALLOWED_FORMATS_LABEL}），其他类型一律拒绝` },
      415
    );
  }

  const ext = canonicalExtForMime(mime);
  if (!ext) {
    return jsonResponse({ error: '不支持的图片格式' }, 415);
  }

  // 4) 重建文件对象：文件名与 MIME 全部由服务端决定
  const fileName = sanitizeFileName(uploadFile.name, ext);
  let safeFile;
  try {
    safeFile = new File([uploadFile], fileName, { type: mime });
  } catch (error) {
    console.error('upload: build safe file failed', error?.message || error);
    return jsonResponse({ error: '文件处理失败' }, 400);
  }

  // 5) 交给 Telegram：只走图片通道
  const result = await sendToTelegram(safeFile, env);
  if (!result.success) {
    console.error('upload: telegram error', result.error);
    return jsonResponse({ error: result.error || '图片上传失败，请稍后重试' }, 502);
  }

  const fileId = getFileId(result.data);
  if (!fileId) {
    return jsonResponse({ error: '未能获取文件标识' }, 502);
  }

  const key = `${fileId}.${ext}`;

  // 6) 记录元数据（KV 未绑定时跳过，不影响上传）
  if (env.img_url) {
    try {
      await env.img_url.put(key, '', {
        metadata: {
          TimeStamp: Date.now(),
          ListType: 'None',
          Label: 'None',
          liked: false,
          fileName,
          fileSize: uploadFile.size,
          mimeType: mime,
        },
      });
    } catch (error) {
      console.error('upload: kv put failed', error?.message || error);
    }
  }

  return jsonResponse([{ src: `/file/${key}` }], 200);
}

/** 非 POST 明确拒绝，避免落到静态资源兜底 */
export async function onRequestGet() {
  return jsonResponse({ error: '请使用 POST 上传' }, 405, { Allow: 'POST' });
}

function getFileId(response) {
  if (!response?.ok || !response.result) return null;

  const result = response.result;
  if (Array.isArray(result.photo) && result.photo.length) {
    return result.photo.reduce((prev, current) =>
      prev.file_size > current.file_size ? prev : current
    ).file_id;
  }
  if (result.document) return result.document.file_id;

  return null;
}

/**
 * 只发送图片：优先 sendPhoto（Telegram 会压缩并生成预览）。
 * 仅当 Telegram 因尺寸/体积拒绝这张**已经通过魔数校验的图片**时，
 * 才降级为 sendDocument 保留原图 —— 降级路径不再接受任意文件。
 */
async function sendToTelegram(file, env) {
  const apiBase = `https://api.telegram.org/bot${env.TG_Bot_Token}`;
  const timeoutMs = Math.min(
    Math.max(Number(env.UPLOAD_TIMEOUT_MS) || 15000, 3000),
    25000
  );

  async function call(method, field) {
    const form = new FormData();
    form.append('chat_id', env.TG_Chat_ID);
    form.append(field, file, file.name);

    // 必须有超时：Telegram 不可达时不能让请求一直挂着，否则并发几个就能把实例拖死
    const signal = typeof AbortSignal !== 'undefined' && AbortSignal.timeout
      ? AbortSignal.timeout(timeoutMs)
      : undefined;

    const response = await fetch(`${apiBase}/${method}`, {
      method: 'POST',
      body: form,
      signal,
    });
    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      data = null;
    }

    if (response.ok && data?.ok) {
      return { success: true, data };
    }
    return {
      success: false,
      fromTelegram: true,
      status: response.status,
      error: data?.description || `Telegram 返回 ${response.status}`,
    };
  }

  let photoResult;
  try {
    photoResult = await call('sendPhoto', 'photo');
  } catch (error) {
    // 网络层失败（超时/连接被拒）不做降级重试，直接失败，避免双倍等待
    console.error('upload: sendPhoto network error', error?.message || error);
    return { success: false, error: '图片上传超时，请稍后重试' };
  }
  if (photoResult.success) return photoResult;

  // 只有 Telegram 明确拒绝这张**已通过魔数校验的图片**时才转文档，仍然是同一张图片
  console.warn('upload: sendPhoto 失败，改用文档方式保留原图:', photoResult.error);
  try {
    const documentResult = await call('sendDocument', 'document');
    if (documentResult.success) return documentResult;
    return { success: false, error: documentResult.error || '图片上传失败' };
  } catch (error) {
    console.error('upload: sendDocument network error', error?.message || error);
    return { success: false, error: '图片上传超时，请稍后重试' };
  }
}
