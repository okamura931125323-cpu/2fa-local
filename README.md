# 本地 2FA 验证器

纯前端 TOTP 验证器，适合部署到 GitHub Pages。

## 安全设计

- TOTP 在浏览器本地使用 Web Crypto API 计算。
- 不包含后端、不发送网络请求。
- CSP 设置 `connect-src 'none'`。
- Secret 不写入 localStorage、sessionStorage、Cookie 或 URL。
- 页面离开/刷新时清理 Secret。
- 支持 Base32 Secret 和标准 `otpauth://totp/...` URI。
- 固定标准参数：6 位、30 秒、HMAC-SHA1。

## GitHub Pages 部署

1. 创建一个新的 GitHub 仓库，例如 `2fa-local`。
2. 上传 `index.html`、`styles.css`、`app.js`。
3. 打开仓库 Settings → Pages。
4. Source 选择 `Deploy from a branch`。
5. Branch 选择默认分支（通常 `main`）和 `/ (root)`，保存。
6. 如需自定义域名，可在 Pages 中填写，例如 `2fa.example.com`，并按 GitHub 提示配置 DNS。

> 不要把真实 2FA Secret 写进仓库里的任何文件。
