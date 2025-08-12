const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const { readLogFiles, startLogWatcher, generateMockLogs, getNodesInformation, getNodeDetails } = require('./logReader');
const path = require('path');
const fsSync = require('fs');

// 🆕 添加Veins配置解析支持
const parseVeinsConfig = () => {
  // 模拟从qca_test.ini读取配置数据（简化版）
  return {
    nodes: {
      rsu: [{ id: 'rsu[0]', x: 2000, y: 2000, z: 3, beaconInterval: 1000 }],
      drones: [{ id: 'drone[0]', x: 1800, y: 2200, z: 50, beaconInterval: 500 }],
      ships: [{ id: 'ship[0]', x: 1500, y: 2500, z: 0, beaconInterval: 2000 }],
      warehouses: [{ id: 'warehouse[0]', x: 1700, y: 1800, z: 0, beaconInterval: 3000 }],
      ports: [{ id: 'port[0]', x: 1600, y: 1700, z: 0, beaconInterval: 2000 }],
      ca: [{ id: 'ca[0]', x: 1000, y: 1250, z: 8, beaconInterval: 500 }],
      qca: [{ id: 'qca[0]', x: 1500, y: 400, z: 0 }]
    },
    security: { qca: true, ca: true },
    playground: { x: 2700, y: 3100, z: 50 }
  };
};

const app = express();
const server = http.createServer(app);

// 配置CORS
app.use(cors({
  origin: ['http://localhost:3000', 'https://survive-in-ncc.netlify.app'],
  credentials: true
}));

app.use(express.json());

// Socket.IO配置
const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:3000', 'https://survive-in-ncc.netlify.app'],
    methods: ["GET", "POST"],
    credentials: true
  }
});

// 添加调试中间件
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// 根路径
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Veins 日志监控服务器运行中',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      logs_all: '/api/logs',
      logs_ca: '/api/logs/ca',
      logs_qca: '/api/logs/qca', 
      logs_veins: '/api/logs/veins',
      health: '/api/health',
      socket: '/socket.io'
    }
  });
});

// 健康检查端点
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: '日志服务器运行正常',
    timestamp: new Date().toISOString(),
    port: 5000,
    nodeEnv: process.env.NODE_ENV || 'development'
  });
});

// 🔥 直接在 server.js 中定义日志API路由
app.get('/api/logs', async (req, res) => {
  try {
    console.log('📥 收到日志请求: all');
    
    const logs = await readLogFiles('all');
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      type: 'all',
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条日志`);
  } catch (error) {
    console.error('❌ 读取所有日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// CA日志端点
app.get('/api/logs/ca', async (req, res) => {
  try {
    console.log('📥 收到CA日志请求');
    
    const logs = await readLogFiles('ca');
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      type: 'ca',
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条CA日志`);
  } catch (error) {
    console.error('❌ 读取CA日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// QCA日志端点
app.get('/api/logs/qca', async (req, res) => {
  try {
    console.log('📥 收到QCA日志请求');
    
    const logs = await readLogFiles('qca');
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      type: 'qca',
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条QCA日志`);
  } catch (error) {
    console.error('❌ 读取QCA日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Veins日志端点
app.get('/api/logs/veins', async (req, res) => {
  try {
    console.log('📥 收到Veins日志请求');
    
    const logs = await readLogFiles('veins');
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      type: 'veins',
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条Veins日志`);
  } catch (error) {
    console.error('❌ 读取Veins日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 通用日志类型处理
app.get('/api/logs/:type', async (req, res) => {
  try {
    const { type } = req.params;
    console.log(`📥 收到 ${type} 类型日志请求`);
    
    const logs = await readLogFiles(type);
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      type: type,
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条 ${type} 日志`);
  } catch (error) {
    console.error(`❌ 读取 ${type} 日志失败:`, error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 🆕 新增：Veins节点配置端点
app.get('/api/veins/config', (req, res) => {
  try {
    console.log('📥 收到Veins配置请求');
    
    const config = parseVeinsConfig();
    
    res.json({
      success: true,
      data: config,
      timestamp: new Date().toISOString()
    });
    
    console.log('📤 返回Veins配置数据');
  } catch (error) {
    console.error('❌ 读取Veins配置失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 获取所有节点信息
app.get('/api/nodes', async (req, res) => {
  try {
    console.log('📥 收到节点信息请求');
    
    const nodesInfo = await getNodesInformation();
    
    res.json({
      success: true,
      data: nodesInfo,
      count: nodesInfo.length,
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${nodesInfo.length} 个节点信息`);
  } catch (error) {
    console.error('❌ 读取节点信息失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 获取特定节点详细信息
app.get('/api/nodes/:nodeId/details', async (req, res) => {
  try {
    const { nodeId } = req.params;
    console.log(`📥 收到节点详情请求: ${nodeId}`);
    
    // 记录更多调试信息
    const veinsCaPath = path.join(__dirname, '../messages/cafiles/nodes', nodeId);
    console.log(`尝试访问的节点路径: ${veinsCaPath}`);
    console.log(`该路径是否存在: ${fsSync.existsSync(veinsCaPath)}`);
    
    const nodeDetails = await getNodeDetails(nodeId);
    
    res.json({
      success: true,
      data: nodeDetails,
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回节点 ${nodeId} 的详细信息`);
  } catch (error) {
    console.error('❌ 读取节点详情失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString(),
      // 添加更多诊断信息
      debug: {
        requestedNodeId: req.params.nodeId,
        configuredPath: path.join(__dirname, '../messages/cafiles/nodes', req.params.nodeId),
        exists: fsSync.existsSync(path.join(__dirname, '../messages/cafiles/nodes', req.params.nodeId))
      }
    });
  }
});

// 添加通信消息路由
const communicationsRouter = require('./routes/communications');
app.use('/api/communications', communicationsRouter);

// Socket.IO连接处理
io.on('connection', (socket) => {
  console.log(`🔌 客户端连接: ${socket.id}`);
  
  // 发送连接确认
  socket.emit('connection_established', {
    message: '已连接到日志服务器',
    timestamp: new Date().toISOString(),
    socketId: socket.id
  });

  // 🆕 发送Veins节点数据
  socket.emit('veins_nodes', {
    type: 'veins_nodes',
    data: parseVeinsConfig(),
    timestamp: new Date().toISOString()
  });

  socket.on('subscribe_logs', (data) => {
    console.log('📋 客户端订阅日志:', data);
    socket.emit('subscription_confirmed', {
      subscriptions: data.logTypes || ['all']
    });
  });

  socket.on('disconnect', (reason) => {
    console.log(`🔌 客户端断开连接: ${socket.id}, 原因: ${reason}`);
  });
});

// 404处理
app.use('*', (req, res) => {
  console.log(`❌ 404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    error: '请求的资源不存在',
    code: 'NOT_FOUND',
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      '/api/health',
      '/api/logs',
      '/api/logs/ca',
      '/api/logs/qca',
      '/api/logs/veins'
    ]
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('🚀 日志服务器启动成功!');
  console.log(`📡 服务器地址: http://localhost:${PORT}`);
  console.log(`🔌 WebSocket服务: ws://localhost:${PORT}`);
  console.log('📋 可用端点:');
  console.log('  - GET /api/health');
  console.log('  - GET /api/logs');
  console.log('  - GET /api/logs/ca');
  console.log('  - GET /api/logs/qca');
  console.log('  - GET /api/logs/veins');
});