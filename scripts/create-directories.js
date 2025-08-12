const fs = require('fs');
const path = require('path');

// 需要创建的目录列表
const directories = [
  './logs',
  './temp',
  './uploads',
  './config',
  '../veins/examples/veins/logs',
  '../veins/cafiles/nodes',
  '../veins/cafiles',
  '../veins/qca'
];

function createDirectories() {
  console.log('🏗️  正在创建必需的目录...');
  
  directories.forEach(dir => {
    const fullPath = path.resolve(__dirname, '..', dir);
    
    try {
      if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
        console.log(`✅ 创建目录: ${fullPath}`);
      } else {
        console.log(`ℹ️  目录已存在: ${fullPath}`);
      }
    } catch (error) {
      console.error(`❌ 创建目录失败 ${fullPath}:`, error.message);
    }
  });
  
  console.log('✨ 目录创建完成！');
}

// 直接执行或作为模块导入
if (require.main === module) {
  createDirectories();
}

module.exports = { createDirectories };