# Veins 日志监控服务器

## 功能特性

- 🚀 **实时日志监控**: 自动读取和解析 Veins V2X 网络日志
- 📊 **多类型支持**: 支持 Veins、CA、QCA、配置文件等多种日志类型
- 🌐 **WebSocket 实时通信**: 实时推送新日志到前端
- 🔍 **高级搜索过滤**: 支持按级别、节点、时间等多维度过滤
- 📈 **统计分析**: 提供详细的日志统计信息
- 🔐 **安全防护**: 内置安全中间件和请求限制
- 📤 **数据导出**: 支持 JSON 和 CSV 格式导出

## 系统要求

- Node.js 16.0.0 或更高版本
- NPM 8.0.0 或更高版本
- Windows 10+ 或 Linux
- 至少 1GB 可用内存

## 快速开始

### 1. 安装依赖

```bash
cd server
npm install
```

### 2. 配置环境变量

复制 `.env.example` 到 `.env` 并根据需要修改配置：

```bash
cp .env.example .env
```

### 3. 启动服务器

**开发模式:**
```bash
npm run dev
```

**生产模式:**
```bash
npm start
```

**使用 PM2 (推荐生产环境):**
```bash
npm run pm2:start
```

### 4. 验证服务

访问 http://localhost:5000/api/health 检查服务状态

## API 文档

### 获取日志

```http
GET /api/logs/:type?
```

**参数:**
- `type`: 日志类型 (all, veins, ca, qca, config)
- `limit`: 限制返回数量 (默认: 1000)
- `offset`: 偏移量 (默认: 0)
- `level`: 日志级别过滤
- `search`: 搜索关键词
- `nodeId`: 节点ID过滤

**示例:**
```bash
curl "http://localhost:5000/api/logs/veins?limit=50&level=ERROR"
```

### 获取统计信息

```http
GET /api/logs/stats/:type?
```

### 高级搜索

```http
POST /api/logs/search
Content-Type: application/json

{
  "query": "vehicle",
  "logType": "veins",
  "filters": {
    "level": "INFO",
    "startTime": "2024-01-01T00:00:00Z"
  }
}
```

## WebSocket 事件

### 客户端发送

- `subscribe_logs`: 订阅日志更新
- `unsubscribe_logs`: 取消订阅
- `request_logs`: 请求实时日志
- `ping`: 保活检测

### 服务器发送

- `connection_established`: 连接建立
- `new_logs`: 新日志推送
- `logs_data`: 日志数据响应
- `pong`: 保活响应

## 目录结构

```
server/
├── server.js              # 主服务器文件
├── logReader.js           # 日志读取器
├── routes/
│   └── logs.js            # 日志 API 路由
├── scripts/
│   └── create-directories.js  # 目录创建脚本
├── logs/                  # 服务器日志目录
├── package.json           # 依赖配置
├── ecosystem.config.js    # PM2 配置
└── .env                   # 环境变量
```

## 生产部署

### 使用 PM2

```bash
# 安装 PM2
npm install -g pm2

# 启动应用
npm run pm2:start

# 查看状态
pm2 status

# 查看日志
npm run pm2:logs

# 重启应用
npm run pm2:restart

# 停止应用
npm run pm2:stop
```

### 使用 Docker

```dockerfile
FROM node:16-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
EXPOSE 5000

CMD ["npm", "start"]
```

## 故障排除

### 1. 端口已被占用

```bash
# 查找占用端口的进程
netstat -ano | findstr :5000

# 终止进程
taskkill /PID <进程ID> /F
```

### 2. 日志文件读取失败

- 检查日志文件路径是否正确
- 确保有足够的文件读取权限
- 验证 Veins 仿真是否正在运行

### 3. WebSocket 连接失败

- 检查防火墙设置
- 验证 CORS 配置
- 确保端口未被阻止

## 开发指南

### 添加新的日志解析器

1. 在 `logReader.js` 中添加解析函数
2. 更新 `LOG_PARSERS` 映射
3. 在 `.env` 中配置新的日志路径

### 扩展 API 端点

1. 在 `routes/logs.js` 中添加新路由
2. 实现相应的处理逻辑
3. 更新 API 文档

## 许可证

MIT License