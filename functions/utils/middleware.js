// 遥测与错误上报已移除（去云依赖）：不再向任何外部服务发送数据。

export async function errorHandling(context) {
  return context.next();
}

export async function telemetryData(context) {
  return context.next();
}

export async function traceData(context, span, op, name) {
  // 遥测已移除，空实现
}
