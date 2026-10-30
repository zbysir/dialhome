/** 「3 分钟前」「还剩 12 分钟」这类话。 */

function span(ms: number): string {
  const m = Math.round(Math.abs(ms) / 60000);
  if (m < 1) return "不到 1 分钟";
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时`;
  return `${Math.floor(h / 24)} 天`;
}

export const ago = (iso: string, now = Date.now()) => span(now - Date.parse(iso)) + "前";
export const left = (iso: string, now = Date.now()) => {
  const ms = Date.parse(iso) - now;
  return ms <= 0 ? "已过期" : "还剩 " + span(ms);
};
export const date = (iso: string) =>
  new Date(iso).toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
