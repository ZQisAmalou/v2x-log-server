const express = require('express');
const router = express.Router();
const { readLogFiles } = require('../logReader');

// 获取所有日志
router.get('/logs', async (req, res) => {
  try {
    console.log('📥 收到日志请求: all');
    
    const logs = await readLogFiles('all');
    
    res.json({
      success: true,
      data: logs,
      count: logs.length,
      timestamp: new Date().toISOString()
    });
    
    console.log(`📤 返回 ${logs.length} 条日志`);
  } catch (error) {
    console.error('❌ 读取日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 按类型获取日志
router.get('/logs/:type', async (req, res) => {
  try {
    const { type } = req.params;
    console.log(`📥 收到日志请求: ${type}`);
    
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
    console.error('❌ 读取日志失败:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;