const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// 通信消息目录
const COMMUNICATIONS_DIR = path.join(__dirname, '../../messages/communications');

// 获取所有节点的通信消息
router.get('/nodes', async (req, res) => {
  try {
    const nodeTypes = ['cas', 'drones', 'ports', 'rsus', 'ships', 'vehicles', 'warehouses'];
    const communications = {};

    for (const nodeType of nodeTypes) {
      const typeDir = path.join(COMMUNICATIONS_DIR, nodeType);
      if (fs.existsSync(typeDir)) {
        const files = fs.readdirSync(typeDir).filter(f => f.endsWith('__messages.txt'));
        communications[nodeType] = {};
        
        for (const file of files) {
          const nodeId = file.replace('__messages.txt', '');
          const filePath = path.join(typeDir, file);
          const content = fs.readFileSync(filePath, 'utf8');
          communications[nodeType][nodeId] = parseMessages(content);
        }
      }
    }

    res.json(communications);
  } catch (error) {
    console.error('获取通信消息失败:', error);
    res.status(500).json({ error: '获取通信消息失败' });
  }
});

// 获取特定节点的通信消息
router.get('/node/:nodeType/:nodeId', async (req, res) => {
  try {
    const { nodeType, nodeId } = req.params;
    const filePath = path.join(COMMUNICATIONS_DIR, nodeType, `${nodeId}__messages.txt`);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: '节点通信消息不存在' });
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const messages = parseMessages(content);
    
    res.json({
      nodeType,
      nodeId,
      messages,
      lastUpdate: fs.statSync(filePath).mtime,
      messageCount: messages.length
    });
  } catch (error) {
    console.error('获取节点通信消息失败:', error);
    res.status(500).json({ error: '获取节点通信消息失败' });
  }
});

// 解析消息内容
function parseMessages(content) {
  const lines = content.split('\n').filter(line => line.trim());
  const messages = [];
  
  for (const line of lines) {
    try {
      // 假设消息格式: [timestamp] [type] message_content
      const match = line.match(/^\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)$/);
      if (match) {
        messages.push({
          timestamp: match[1],
          type: match[2],
          content: match[3],
          id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        });
      } else {
        // 如果格式不匹配，直接存储原始内容
        messages.push({
          timestamp: new Date().toISOString(),
          type: 'raw',
          content: line,
          id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        });
      }
    } catch (error) {
      console.error('解析消息行失败:', line, error);
    }
  }
  
  return messages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

module.exports = router;