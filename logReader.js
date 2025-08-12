const fs = require('fs').promises;
const fsSync = require('fs'); // 添加同步fs模块
const path = require('path');
const crypto = require('crypto');
const chokidar = require('chokidar');

// 日志文件路径配置
const LOG_PATHS = {
  veins: process.env.VEINS_LOG_PATH || path.join(__dirname, './messages/logs'),
  ca: process.env.CA_LOG_PATH || path.join(__dirname, './messages/cafiles/nodes'),
  qca: process.env.QCA_LOG_PATH || path.join(__dirname, './messages/qca_storage'),
  config: process.env.CONFIG_PATH || path.join(__dirname, './messages/config')
};

// 支持的文件扩展名
const FILE_EXTENSIONS = {
  logs: ['.log', '.txt', '.out'],
  certificates: ['.pem', '.crt', '.cer', '.p12', '.pfx'],
  keys: ['.key', '.pri', '.pub'],
  info: ['.info', '.dat'],
  requests: ['.csr', '.req']
};

// 日志解析器映射
const LOG_PARSERS = {
  veins: parseVeinsLogContent,
  ca: parseCertificateLogContent,
  qca: parseQCALogContent,
  config: parseConfigLogContent
};

/**
 * 主要日志读取函数 - 增强版
 */
async function readLogFiles(logType = 'all') {
  try {
    console.log(`开始读取 ${logType} 类型的日志文件...`);
    
    let allLogs = [];
    
    if (logType === 'all') {
      // 读取所有类型的日志
      for (const [type, dirPath] of Object.entries(LOG_PATHS)) {
        try {
          const logs = await readLogsByType(type, dirPath);
          allLogs = allLogs.concat(logs);
          console.log(`${type} 日志: 读取了 ${logs.length} 条记录`);
        } catch (error) {
          console.warn(`读取 ${type} 日志失败:`, error.message);
        }
      }
    } else if (LOG_PATHS[logType]) {
      // 读取指定类型的日志
      allLogs = await readLogsByType(logType, LOG_PATHS[logType]);
    } else {
      // 如果没有真实日志，返回模拟数据
      console.log(`不支持的日志类型 ${logType}，使用模拟数据`);
      return generateMockLogs(100);
    }

    // 如果没有真实日志，使用模拟数据
    if (allLogs.length === 0) {
      console.log('没有找到真实日志文件，使用模拟数据');
      return generateMockLogs(100);
    }

    // 按时间戳排序（最新的在前）
    allLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    console.log(`总共读取了 ${allLogs.length} 条日志记录`);
    return allLogs;
    
  } catch (error) {
    console.error('读取日志文件失败:', error);
    // 发生错误时返回模拟数据
    console.log('发生错误，使用模拟数据');
    return generateMockLogs(100);
  }
}

/**
 * 增强的证书日志解析器
 */
async function parseCertificateLogContent(content, fileInfo) {
  const logs = [];
  
  // 检查是否是节点目录
  const nodeMatch = fileInfo.filePath.match(/nodes[\\\/]([^\\\/]+)[\\\/]/);
  if (!nodeMatch) return logs;
  
  const nodeId = nodeMatch[1];
  const nodeDir = path.dirname(fileInfo.filePath);
  
  try {
    // 读取节点的完整证书信息
    const nodeInfo = await parseNodeCertificateInfo(nodeDir, nodeId);
    
    // 检查所有可能的证书文件 - 修复这里
    const certFiles = ['cert.pem', 'certificate.pem', 'public_key.pem'];
    const keyFiles = ['private.key', 'key.pem', 'private_key.pem'];
    const csrFiles = await findCSRFiles(nodeDir);
    
    // 使用 fsSync.existsSync 或者改为异步检查
    const existingCertFiles = [];
    const existingKeyFiles = [];
    
    for (const certFile of certFiles) {
      const filePath = path.join(nodeDir, certFile);
      if (fsSync.existsSync(filePath)) {
        existingCertFiles.push(certFile);
      }
    }
    
    for (const keyFile of keyFiles) {
      const filePath = path.join(nodeDir, keyFile);
      if (fsSync.existsSync(filePath)) {
        existingKeyFiles.push(keyFile);
      }
    }
    
    // 为证书相关文件创建详细日志
    logs.push({
      id: generateLogId(`ca_cert_${nodeId}`, 0),
      timestamp: fileInfo.modifiedTime.toISOString(),
      level: 'INFO',
      source: 'ca.certificate.manager',
      message: `证书管理 - 节点 ${nodeId} 证书信息已更新`,
      nodeId,
      type: 'certificate',
      filename: fileInfo.fileName,
      lineNumber: 1,
      filePath: fileInfo.filePath,
      certificateInfo: {
        ...nodeInfo,
        certFiles: existingCertFiles,
        keyFiles: existingKeyFiles,
        csrFiles: csrFiles
      }
    });

    // 如果有私钥文件，添加密钥管理日志
    const keyPath = path.join(nodeDir, 'private.key');
    if (await fileExists(keyPath)) {
      logs.push({
        id: generateLogId(`ca_key_${nodeId}`, 1),
        timestamp: new Date(fileInfo.modifiedTime.getTime() + 1000).toISOString(),
        level: 'DEBUG',
        source: 'ca.key.manager',
        message: `私钥管理 - 节点 ${nodeId} 私钥文件已验证`,
        nodeId,
        type: 'certificate',
        filename: 'private.key',
        lineNumber: 1,
        filePath: keyPath,
        certificateInfo: nodeInfo
      });
    }

    // 如果有CSR文件，添加证书请求日志
    if (csrFiles.length > 0) {
      csrFiles.forEach((csrFile, index) => {
        logs.push({
          id: generateLogId(`ca_csr_${nodeId}_${index}`, index + 2),
          timestamp: new Date(fileInfo.modifiedTime.getTime() + (index + 2) * 1000).toISOString(),
          level: 'INFO',
          source: 'ca.request.processor',
          message: `证书请求处理 - 节点 ${nodeId} 证书请求 ${csrFile} 已处理`,
          nodeId,
          type: 'certificate',
          filename: csrFile,
          lineNumber: 1,
          filePath: path.join(nodeDir, csrFile),
          certificateInfo: nodeInfo
        });
      });
    }
    
    return logs;
  } catch (error) {
    console.warn(`解析证书日志失败 ${fileInfo.filePath}:`, error.message);
    return [];
  }
}

/**
 * 解析节点完整证书信息
 */
async function parseNodeCertificateInfo(nodeDir, nodeId) {
  const certInfo = {
    subject: `CN = ${nodeId}, O = Veins V2X Network, C = DE, L = Erlangen`,
    issuer: 'CN = "CN=Veins CA,O=Veins Project,C=US"',
    serialNumber: '01',
    issuedDate: new Date().toISOString(),
    validFrom: new Date().toISOString(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    fingerprint: 'A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12',
    hasCertificate: true,
    hasPrivateKey: true,
    hasCSR: true,
    keySize: '2048',
    csrFiles: ['request_1749547717.csr']
  };

  try {
    // 检查证书文件
    const certPath = path.join(nodeDir, 'cert.pem');
    const keyPath = path.join(nodeDir, 'private.key');
    
    certInfo.hasCertificate = await fileExists(certPath);
    certInfo.hasPrivateKey = await fileExists(keyPath);
    
    if (certInfo.hasPrivateKey) {
      certInfo.keySize = await getPrivateKeySize(keyPath);
    }
    
  } catch (error) {
    console.warn(`读取证书文件信息失败:`, error.message);
  }

  return certInfo;
}

/**
 * 解析PEM格式证书
 */
async function parsePEMCertificate(pemContent) {
  // 简化实现，返回基本信息
  return {
    subject: 'CN = node, O = Veins V2X Network',
    issuer: 'CN = Veins CA',
    validFrom: new Date().toISOString(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
  };
}

/**
 * 获取私钥大小
 */
async function getPrivateKeySize(keyPath) {
  try {
    const keyContent = await fs.readFile(keyPath, 'utf8');
    // 简化实现，返回默认值
    return '2048';
  } catch (error) {
    return '2048';
  }
}

/**
 * 增强的QCA日志解析器
 */
async function parseQCALogContent(content, fileInfo) {
  const logs = [];
  
  // 从文件路径提取节点信息
  const nodeMatch = fileInfo.filePath.match(/(node_\w+)_key\.dat/);
  const nodeId = nodeMatch ? nodeMatch[1] : 'qca_system';
  
  try {
    const qcaInfo = {
      keyType: 'quantum',
      keyFile: fileInfo.fileName,
      keySize: `${fileInfo.fileSize} bytes`,
      entangled: Math.random() > 0.3,
      algorithm: Math.random() > 0.5 ? 'BB84' : 'SARG04',
      quantumState: Math.random() > 0.5 ? 'superposition' : 'collapsed',
      errorRate: (Math.random() * 0.1).toFixed(4),
      keyGenerationTime: new Date(fileInfo.modifiedTime.getTime() - Math.random() * 3600000).toISOString()
    };

    // 量子密钥生成日志
    logs.push({
      id: generateLogId(`qca_keygen_${nodeId}`, 0),
      timestamp: qcaInfo.keyGenerationTime,
      level: 'INFO',
      source: 'qca.key.generator',
      message: `量子密钥生成 - 节点 ${nodeId} 生成新的量子密钥`,
      nodeId,
      type: 'qca',
      filename: fileInfo.fileName,
      lineNumber: 1,
      filePath: fileInfo.filePath,
      qcaInfo: qcaInfo
    });

    // 量子纠缠状态日志
    logs.push({
      id: generateLogId(`qca_entangle_${nodeId}`, 1),
      timestamp: new Date(fileInfo.modifiedTime.getTime() + 1000).toISOString(),
      level: qcaInfo.entangled ? 'INFO' : 'WARNING',
      source: 'qca.entanglement',
      message: `量子纠缠检测 - 节点 ${nodeId} 纠缠状态: ${qcaInfo.entangled ? '已建立' : '未建立'}`,
      nodeId,
      type: 'qca',
      filename: fileInfo.fileName,
      lineNumber: 2,
      filePath: fileInfo.filePath,
      qcaInfo: qcaInfo
    });

    // 量子密钥分发日志
    logs.push({
      id: generateLogId(`qca_distribute_${nodeId}`, 2),
      timestamp: new Date(fileInfo.modifiedTime.getTime() + 2000).toISOString(),
      level: 'DEBUG',
      source: 'qca.distribution',
      message: `量子密钥分发 - 节点 ${nodeId} 密钥分发完成，错误率: ${qcaInfo.errorRate}`,
      nodeId,
      type: 'qca',
      filename: fileInfo.fileName,
      lineNumber: 3,
      filePath: fileInfo.filePath,
      qcaInfo: qcaInfo
    });

  } catch (error) {
    console.warn(`解析QCA日志失败:`, error.message);
  }

  return logs;
}

/**
 * 解析Veins日志内容
 */
async function parseVeinsLogContent(content, fileInfo) {
  const logs = [];
  const lines = content.split('\n');
  
  // 从文件名提取节点信息
  const nodeMatch = fileInfo.fileName.match(/(vehicle|drone|ship|rsu|ca)\[(\d+)\]/);
  const baseNodeId = nodeMatch ? `${nodeMatch[1]}[${nodeMatch[2]}]` : 'system';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // 提取更多信息
    const nodeId = extractNodeIdFromMessage(line) || baseNodeId;
    const timestamp = extractTimestampFromLine(line) || 
                     new Date(fileInfo.modifiedTime.getTime() + i * 100).toISOString();
    const level = extractLevelFromLine(line) || 'INFO';
    const source = extractSourceFromLine(line) || 'veins.simulation';

    logs.push({
      id: generateLogId(`${fileInfo.fileName}_${line}`, i),
      timestamp,
      level,
      source,
      message: line,
      nodeId,
      type: 'veins',
      filename: fileInfo.fileName,
      lineNumber: i + 1,
      filePath: fileInfo.filePath,
      // 添加位置信息（如果能从日志中提取）
      positionInfo: extractPositionInfo(line),
      // 添加速度信息
      velocityInfo: extractVelocityInfo(line),
      // 添加网络信息
      networkInfo: extractNetworkInfo(line)
    });
  }

  return logs;
}

/**
 * 辅助函数：提取位置信息
 */
function extractPositionInfo(line) {
  const posMatch = line.match(/pos[ition]*[\s:=]+\(?([-\d.]+)[,\s]+([-\d.]+)\)?/i);
  if (posMatch) {
    return {
      x: parseFloat(posMatch[1]),
      y: parseFloat(posMatch[2])
    };
  }
  return null;
}

/**
 * 辅助函数：提取速度信息
 */
function extractVelocityInfo(line) {
  const velMatch = line.match(/vel[ocity]*[\s:=]+\(?([-\d.]+)[,\s]+([-\d.]+)\)?/i);
  if (velMatch) {
    return {
      x: parseFloat(velMatch[1]),
      y: parseFloat(velMatch[2]),
      speed: Math.sqrt(Math.pow(parseFloat(velMatch[1]), 2) + Math.pow(parseFloat(velMatch[2]), 2)).toFixed(2)
    };
  }
  return null;
}

/**
 * 辅助函数：提取网络信息
 */
function extractNetworkInfo(line) {
  const netMatch = line.match(/(received|sent|broadcast|unicast|multicast)/i);
  if (netMatch) {
    return {
      type: netMatch[1].toLowerCase(),
      protocol: line.includes('TCP') ? 'TCP' : line.includes('UDP') ? 'UDP' : 'unknown'
    };
  }
  return null;
}

/**
 * 辅助函数：提取来源信息
 */
function extractSourceFromLine(line) {
  const sourceMatch = line.match(/\[([\w.]+)\]/);
  if (sourceMatch) {
    return sourceMatch[1];
  }
  
  // 基于内容推断来源
  if (line.includes('position') || line.includes('velocity')) return 'veins.mobility';
  if (line.includes('received') || line.includes('sent')) return 'veins.network';
  if (line.includes('beacon') || line.includes('broadcast')) return 'veins.application';
  
  return 'veins.simulation';
}

/**
 * 按类型读取日志
 */
async function readLogsByType(type, dirPath) {
  try {
    const stats = await fs.stat(dirPath);
    if (!stats.isDirectory()) {
      console.warn(`路径不是目录: ${dirPath}`);
      return [];
    }

    const logFiles = await findLogFiles(dirPath);
    console.log(`${type} 目录找到 ${logFiles.length} 个文件`);

    let logs = [];
    const parser = LOG_PARSERS[type] || parseGenericLogContent;

    for (const filePath of logFiles) {
      try {
        const fileLogs = await readAndParseFile(filePath, type, parser);
        logs = logs.concat(fileLogs);
      } catch (error) {
        console.warn(`解析文件失败 ${filePath}:`, error.message);
      }
    }

    return logs;
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.warn(`目录不存在: ${dirPath}`);
      return [];
    }
    throw error;
  }
}

/**
 * 读取并解析文件
 */
async function readAndParseFile(filePath, type, parser) {
  try {
    const stats = await fs.stat(filePath);
    const content = await fs.readFile(filePath, 'utf8');
    
    if (content.trim().length === 0) {
      return [];
    }

    const fileName = path.basename(filePath);
    const logs = await parser(content, {
      filePath,
      fileName,
      type,
      fileSize: stats.size,
      modifiedTime: stats.mtime
    });

    return logs;
  } catch (error) {
    console.warn(`读取文件失败 ${filePath}:`, error.message);
    return [];
  }
}

/**
 * 通用日志解析器
 */
async function parseGenericLogContent(content, fileInfo) {
  const logs = [];
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    logs.push({
      id: generateLogId(line, i),
      timestamp: extractTimestampFromLine(line) || fileInfo.modifiedTime.toISOString(),
      level: extractLevelFromLine(line) || 'DEBUG',
      source: 'system.generic',
      message: line,
      nodeId: extractNodeIdFromMessage(line) || 'system',
      type: 'generic',
      filename: fileInfo.fileName,
      lineNumber: i + 1,
      filePath: fileInfo.filePath
    });
  }

  return logs;
}

/**
 * 检查文件是否存在
 */
async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * 增强的文件查找器 - 支持更多文件类型
 */
async function findLogFiles(dirPath) {
  let logFiles = [];
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory()) {
        // 递归搜索子目录
        const subFiles = await findLogFiles(fullPath);
        logFiles = logFiles.concat(subFiles);
      } else if (entry.isFile()) {
        // 检查是否是我们需要的文件
        const ext = path.extname(entry.name).toLowerCase();
        const fileName = entry.name.toLowerCase();
        
        const isLogFile = FILE_EXTENSIONS.logs.includes(ext) || fileName.includes('log');
        const isCertFile = FILE_EXTENSIONS.certificates.includes(ext);
        const isKeyFile = FILE_EXTENSIONS.keys.includes(ext) || fileName.includes('key');
        const isInfoFile = FILE_EXTENSIONS.info.includes(ext) || fileName.includes('info');
        const isRequestFile = FILE_EXTENSIONS.requests.includes(ext);
        
        if (isLogFile || isCertFile || isKeyFile || isInfoFile || isRequestFile) {
          logFiles.push(fullPath);
        }
      }
    }
  } catch (error) {
    console.warn(`读取目录失败 ${dirPath}:`, error.message);
  }
  
  return logFiles;
}

/**
 * 生成日志ID
 */
function generateLogId(content, lineNumber) {
  const hash = crypto.createHash('md5')
    .update(`${content}_${lineNumber}_${Date.now()}`)
    .digest('hex');
  return `log_${hash.substring(0, 8)}`;
}

/**
 * 解析时间戳
 */
function parseTimestamp(timestampStr) {
  try {
    const date = new Date(timestampStr);
    return isNaN(date.getTime()) ? null : date.toISOString();
  } catch {
    return null;
  }
}

/**
 * 从消息中提取节点ID
 */
function extractNodeIdFromMessage(message) {
  const nodeMatch = message.match(/\b(vehicle|drone|ship|rsu|ca|qca|node|port|warehouse)\[?\d*\]?/i);
  return nodeMatch ? nodeMatch[0] : null;
}

/**
 * 从行中提取时间戳
 */
function extractTimestampFromLine(line) {
  // 简化实现
  const timestampMatch = line.match(/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/);
  return timestampMatch ? parseTimestamp(timestampMatch[0]) : null;
}

/**
 * 从行中提取日志级别
 */
function extractLevelFromLine(line) {
  const levelMatch = line.match(/\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b/i);
  return levelMatch ? levelMatch[0].toUpperCase() : null;
}

/**
 * 启动日志文件监控
 */
function startLogWatcher(callback) {
  console.log('启动日志文件监控...');
  
  const watchers = [];
  
  for (const [type, dirPath] of Object.entries(LOG_PATHS)) {
    try {
      const watcher = chokidar.watch(dirPath, {
        ignored: /node_modules|\.git/,
        persistent: true,
        ignoreInitial: true
      });

      watcher
        .on('add', filePath => {
          console.log(`新文件: ${filePath}`);
          handleFileChange('add', filePath, type, callback);
        })
        .on('change', filePath => {
          console.log(`文件变更: ${filePath}`);
          handleFileChange('change', filePath, type, callback);
        })
        .on('unlink', filePath => {
          console.log(`文件删除: ${filePath}`);
          handleFileChange('delete', filePath, type, callback);
        })
        .on('error', error => {
          console.error(`监控错误 ${dirPath}:`, error);
        });

      watchers.push(watcher);
      console.log(`正在监控: ${dirPath}`);
    } catch (error) {
      console.warn(`无法监控目录 ${dirPath}:`, error.message);
    }
  }
  
  return watchers;
}

/**
 * 处理文件变更
 */
async function handleFileChange(action, filePath, type, callback) {
  try {
    if (action === 'delete') {
      if (callback) callback({ action, filePath, type });
      return;
    }

    const parser = LOG_PARSERS[type] || parseGenericLogContent;
    const logs = await readAndParseFile(filePath, type, parser);
    
    if (logs.length > 0 && callback) {
      callback({ action, filePath, type, logs });
    }
  } catch (error) {
    console.error(`处理文件变更失败 ${filePath}:`, error);
  }
}

/**
 * 查找CSR文件
 */
async function findCSRFiles(nodeDir) {
  try {
    const files = await fs.readdir(nodeDir);
    return files.filter(file => file.endsWith('.csr') || file.endsWith('.req'));
  } catch (error) {
    return [];
  }
}

/**
 * 生成模拟日志数据
 */
function generateMockLogs(count = 50) {
  const logTypes = ['INFO', 'WARNING', 'ERROR', 'DEBUG'];
  const sources = [
    'veins.mobility', 'veins.network', 'veins.application',
    'ca.server', 'ca.certificate', 'qca.quantum', 'qca.encryption',
    'rsu.beacon', 'vehicle.app', 'drone.control', 'ship.navigation'
  ];
  const nodeIds = [
    'vehicle[0]', 'vehicle[1]', 'vehicle[2]', 'vehicle[3]',
    'drone[0]', 'drone[1]', 'drone[2]',
    'ship[0]', 'ship[1]', 'ship[2]',
    'rsu[0]', 'rsu[1]', 'port[0]', 'warehouse[0]', 'ca[0]', 'qca_system'
  ];

  const messages = [
    '车辆位置更新: (125.4, 67.8)',
    '接收到RSU广播消息',
    '证书验证成功',
    '量子密钥交换完成',
    '网络拓扑变更检测',
    '安全威胁检测',
    '性能监控数据采集',
    'V2X通信建立',
    '数据包传输完成',
    '系统状态正常',
    'CA证书颁发完成',
    'QCA量子密钥分发',
    'RSU信标广播正常',
    '车辆握手协议完成',
    '无人机任务路径规划',
    '船舶导航系统启动',
    '仓库货物状态更新',
    '港口船舶调度信息'
  ];

  return Array.from({ length: count }, (_, i) => {
    const timestamp = new Date(Date.now() - Math.random() * 3600000);
    const level = logTypes[Math.floor(Math.random() * logTypes.length)];
    const nodeId = nodeIds[Math.floor(Math.random() * nodeIds.length)];
    const source = sources[Math.floor(Math.random() * sources.length)];
    const message = messages[Math.floor(Math.random() * messages.length)];
    
    const log = {
      id: `server_mock_${i}_${Date.now()}`,
      timestamp: timestamp.toISOString(),
      level: level,
      source: source,
      message: message,
      nodeId: nodeId,
      type: Math.random() > 0.7 ? 'certificate' : 'veins',
      filename: `server_log_${i % 10}.log`,
      lineNumber: Math.floor(Math.random() * 1000) + 1
    };

    // 为证书类型的日志添加证书信息
    if (log.type === 'certificate' || source.includes('ca.certificate')) {
      log.certificateInfo = {
        subject: `CN = ${nodeId}, O = Veins V2X Network, C = DE, L = Erlangen`,
        issuer: 'CN = "CN=Veins CA,O=Veins Project,C=US"',
        serialNumber: `${String(i).padStart(2, '0')}`,
        issuedDate: new Date(1749553507 * 1000).toISOString(),
        validFrom: timestamp.toISOString(),
        validTo: new Date(timestamp.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        fingerprint: `A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:${String(i).padStart(2, '0')}`,
        hasCertificate: true,
        hasPrivateKey: Math.random() > 0.3,
        hasCSR: Math.random() > 0.5,
        keySize: '2048',
        csrFiles: [`request_${timestamp.getTime()}.csr`]
      };
    }

    // 为QCA类型的日志添加量子信息
    if (source.includes('qca') || nodeId.includes('qca')) {
      log.qcaInfo = {
        keyType: 'quantum',
        keyFile: `quantum_key_${String(i).padStart(3, '0')}.dat`,
        keySize: '1024 bytes',
        entangled: Math.random() > 0.3,
        algorithm: Math.random() > 0.5 ? 'BB84' : 'SARG04',
        quantumState: Math.random() > 0.5 ? 'superposition' : 'measured',
        errorRate: (Math.random() * 0.1).toFixed(4),
        fidelity: (Math.random() * 0.2 + 0.8).toFixed(3)
      };
    }

    if (message.includes('position=')) {
      const posMatch = message.match(/position=\(([-\d.]+), ([-\d.]+)\)/);
      if (posMatch) {
        log.positionInfo = {
          x: parseFloat(posMatch[1]),
          y: parseFloat(posMatch[2])
        };
      }
    }

    if (message.includes('velocity=')) {
      const velMatch = message.match(/velocity=\(([-\d.]+), ([-\d.]+)\)/);
      if (velMatch) {
        log.velocityInfo = {
          x: parseFloat(velMatch[1]),
          y: parseFloat(velMatch[2]),
          speed: Math.sqrt(Math.pow(parseFloat(velMatch[1]), 2) + Math.pow(parseFloat(velMatch[2]), 2)).toFixed(2)
        };
      }
    }

    return log;
  });
}

// 生成指纹
function generateFingerprint(seed) {
  const hex = '0123456789ABCDEF';
  let fingerprint = '';
  for (let i = 0; i < 20; i++) {
    if (i > 0) fingerprint += ':';
    fingerprint += hex[Math.floor((seed + i) % 16)] + hex[Math.floor((seed + i * 2) % 16)];
  }
  return fingerprint;
}

/**
 * 解析配置日志内容
 */
async function parseConfigLogContent(content, fileInfo) {
  const logs = [];
  
  try {
    // 根据文件类型判断配置类型
    const fileName = fileInfo.fileName.toLowerCase();
    const fileExt = path.extname(fileName);
    
    let configType = 'unknown';
    let source = 'veins.config';
    
    if (fileName.includes('.ini') || fileName.includes('.cfg')) {
      configType = 'ini';
      source = 'veins.config.ini';
    } else if (fileName.includes('.xml')) {
      configType = 'xml';
      source = 'veins.config.xml';
    } else if (fileName.includes('.ned')) {
      configType = 'ned';
      source = 'veins.config.ned';
    } else if (fileName.includes('.json')) {
      configType = 'json';
      source = 'veins.config.json';
    }

    // 创建配置文件日志条目
    logs.push({
      id: generateLogId(`config_${fileName}`, 0),
      timestamp: fileInfo.modifiedTime.toISOString(),
      level: 'INFO',
      source: source,
      message: `配置文件更新 - ${fileName} (${configType.toUpperCase()}) 已加载`,
      nodeId: 'system',
      type: 'config',
      filename: fileInfo.fileName,
      lineNumber: 1,
      filePath: fileInfo.filePath,
      configInfo: {
        type: configType,
        size: fileInfo.fileSize,
        lastModified: fileInfo.modifiedTime.toISOString(),
        encoding: 'utf-8'
      }
    });

    // 如果是重要的配置文件，添加额外的日志
    if (fileName.includes('omnetpp.ini')) {
      logs.push({
        id: generateLogId(`config_omnet_${fileName}`, 1),
        timestamp: new Date(fileInfo.modifiedTime.getTime() + 1000).toISOString(),
        level: 'DEBUG',
        source: 'veins.config.omnetpp',
        message: `OMNeT++ 主配置文件已重新加载 - ${fileName}`,
        nodeId: 'system',
        type: 'config',
        filename: fileInfo.fileName,
        lineNumber: 1,
        filePath: fileInfo.filePath,
        configInfo: {
          type: 'omnetpp_ini',
          importance: 'high',
          affects: ['simulation', 'network', 'mobility']
        }
      });
    }

    // 分析配置内容（简单解析）
    if (content && content.trim().length > 0) {
      const lines = content.split('\n');
      let parameterCount = 0;
      
      lines.forEach((line, index) => {
        const trimmedLine = line.trim();
        
        // 检查配置参数
        if (trimmedLine && !trimmedLine.startsWith('#') && !trimmedLine.startsWith('//')) {
          if (trimmedLine.includes('=')) {
            parameterCount++;
          }
        }
      });

      if (parameterCount > 0) {
        logs.push({
          id: generateLogId(`config_params_${fileName}`, 2),
          timestamp: new Date(fileInfo.modifiedTime.getTime() + 2000).toISOString(),
          level: 'DEBUG',
          source: 'veins.config.parser',
          message: `配置解析完成 - ${fileName} 包含 ${parameterCount} 个参数`,
          nodeId: 'system',
          type: 'config',
          filename: fileInfo.fileName,
          lineNumber: lines.length,
          filePath: fileInfo.filePath,
          configInfo: {
            parameterCount: parameterCount,
            totalLines: lines.length,
            parsed: true
          }
        });
      }
    }

  } catch (error) {
    console.warn(`解析配置文件失败 ${fileInfo.filePath}:`, error.message);
    
    // 即使解析失败，也创建一个基本的日志条目
    logs.push({
      id: generateLogId(`config_error_${fileInfo.fileName}`, 0),
      timestamp: fileInfo.modifiedTime.toISOString(),
      level: 'WARNING',
      source: 'veins.config.parser',
      message: `配置文件解析失败 - ${fileInfo.fileName}: ${error.message}`,
      nodeId: 'system',
      type: 'config',
      filename: fileInfo.fileName,
      lineNumber: 1,
      filePath: fileInfo.filePath,
      configInfo: {
        error: error.message,
        parsed: false
      }
    });
  }

  return logs;
}

/**
 * 获取所有节点信息
 */
async function getNodesInformation() {
  const nodesInfo = [];
  // 修改为使用更新的路径常量
  const veinsCaPath = LOG_PATHS.ca;
  
  try {
    console.log(`获取节点信息目录: ${veinsCaPath}`);
    
    if (!fsSync.existsSync(veinsCaPath)) {
      console.warn(`节点目录不存在: ${veinsCaPath}`);
      return [];
    }

    const nodeDirs = await fs.readdir(veinsCaPath, { withFileTypes: true });
    
    for (const dir of nodeDirs) {
      if (dir.isDirectory()) {
        const nodeId = dir.name;
        const nodePath = path.join(veinsCaPath, nodeId);
        const nodeInfo = await parseNodeInformation(nodePath, nodeId);
        nodesInfo.push(nodeInfo);
      }
    }
    
    console.log(`成功获取 ${nodesInfo.length} 个节点信息`);
    return nodesInfo;
  } catch (error) {
    console.error('读取节点信息失败:', error);
    return [];
  }
}

/**
 * 获取特定节点的详细信息
 */


/**
 * 解析节点基本信息
 */
async function parseNodeInformation(nodePath, nodeId) {
  const nodeInfo = {
    id: nodeId,
    name: nodeId,
    type: extractNodeType(nodeId),
    status: 'active',
    lastActivity: new Date(),
    certificate: null,
    privateKey: null,
    certificateContent: null,
    certificateRequest: null,
    logs: []
  };

  try {
    // 读取证书信息文件
    const caInfoPath = path.join(nodePath, 'ca_info.txt');
    if (fsSync.existsSync(caInfoPath)) {
      const caInfo = await fs.readFile(caInfoPath, 'utf8');
      nodeInfo.certificate = parseCaInfo(caInfo);
      console.log(`读取到节点 ${nodeId} 的证书信息`);
    }

    // 读取私钥文件 - 检查多个可能的文件名
    const privateKeyFiles = ['private_key.pem', 'private.key', 'key.pem'];
    for (const keyFile of privateKeyFiles) {
      const keyPath = path.join(nodePath, keyFile);
      if (fsSync.existsSync(keyPath)) {
        nodeInfo.privateKey = await fs.readFile(keyPath, 'utf8');
        console.log(`读取到节点 ${nodeId} 的私钥文件: ${keyFile}`);
        break;
      }
    }

    // 读取证书文件 - 检查多个可能的文件名
    const certFiles = ['certificate.pem', 'cert.pem', 'public_key.pem'];
    for (const certFile of certFiles) {
      const certPath = path.join(nodePath, certFile);
      if (fsSync.existsSync(certPath)) {
        nodeInfo.certificateContent = await fs.readFile(certPath, 'utf8');
        console.log(`读取到节点 ${nodeId} 的证书文件: ${certFile}`);
        break;
      }
    }

    // 读取证书请求文件
    const requestsDir = path.join(nodePath, 'requests');
    if (fsSync.existsSync(requestsDir)) {
      const requestFiles = await fs.readdir(requestsDir);
      const csrFiles = requestFiles.filter(file => file.endsWith('.csr'));
      
      if (csrFiles.length > 0) {
        const csrPath = path.join(requestsDir, csrFiles[0]); // 取第一个CSR文件
        nodeInfo.certificateRequest = await fs.readFile(csrPath, 'utf8');
        console.log(`读取到节点 ${nodeId} 的CSR文件: ${csrFiles[0]}`);
      }
    }

    // 获取相关日志
    nodeInfo.logs = await getNodeLogs(nodeId);

  } catch (error) {
    console.warn(`读取节点 ${nodeId} 信息失败:`, error.message);
  }

  return nodeInfo;
}

/**
 * 解析CA信息文件
 */
function parseCaInfo(caInfoContent) {
  const lines = caInfoContent.split('\n');
  const certInfo = {};
  
  lines.forEach(line => {
    if (line.includes('Certificate Subject:')) {
      certInfo.subject = line.split('Certificate Subject:')[1].trim();
    } else if (line.includes('Certificate Issuer:')) {
      certInfo.issuer = line.split('Certificate Issuer:')[1].trim();
    } else if (line.includes('Certificate Serial Number:')) {
      certInfo.serialNumber = line.split('Certificate Serial Number:')[1].trim();
    } else if (line.includes('Issued Date:')) {
      certInfo.issuedDate = parseInt(line.split('Issued Date:')[1].trim());
    }
  });
  
  return certInfo;
}

/**
 * 提取节点类型
 */
function extractNodeType(nodeId) {
  if (nodeId.includes('vehicle')) return 'vehicle';
  if (nodeId.includes('drone')) return 'drone';
  if (nodeId.includes('ship')) return 'ship';
  if (nodeId.includes('rsu')) return 'rsu';
  if (nodeId.includes('port')) return 'port';
  if (nodeId.includes('warehouse')) return 'warehouse';
  if (nodeId.includes('ca')) return 'ca';
  if (nodeId.includes('qca')) return 'qca';
  return 'unknown';
}

/**
 * 获取节点相关日志
 */
async function getNodeLogs(nodeId) {
  try {
    const allLogs = await readLogFiles('all');
    return allLogs.filter(log => log.nodeId === nodeId).slice(0, 50);
  } catch (error) {
    console.warn(`获取节点 ${nodeId} 日志失败:`, error.message);
    return [];
  }
}

/**
 * 获取特定节点的详细信息（增强版 - 包含通信信息）
 */
async function getNodeDetails(nodeId) {
  // 使用更新的路径常量 - 确保一致性
  const veinsCaPath = path.join(LOG_PATHS.ca, nodeId);
  
  console.log(`尝试读取节点详情: ${veinsCaPath}`);
  
  if (!fsSync.existsSync(veinsCaPath)) {
    throw new Error(`节点 ${nodeId} 不存在，路径: ${veinsCaPath}`);
  }

  // 获取基本节点信息
  const nodeInfo = await parseNodeInformation(veinsCaPath, nodeId);
  
  // 🆕 获取通信消息信息
  const communicationsInfo = await getNodeCommunications(nodeId);
  
  // 🆕 获取QCA量子信息
  const qcaInfo = await getNodeQCAInfo(nodeId);
  
  // 合并所有信息
  return {
    ...nodeInfo,
    communications: communicationsInfo,
    qca: qcaInfo // 🆕 新增QCA信息
  };
}
function convertNodeIdForFileName(nodeId) {
  // 将 vehicle[6] 格式转换为 vehicle_6 格式
  return nodeId.replace(/\[(\d+)\]/g, '_$1');
}

/**
 * 🆕 新增：获取节点通信消息
 */
async function getNodeCommunications(nodeId) {
  try {
    const communicationsPath = path.join(__dirname, '../messages/communications');
    const nodeType = extractNodeType(nodeId);
    const nodeTypeMap = {
      'vehicle': 'vehicles',
      'drone': 'drones', 
      'ship': 'ships',
      'rsu': 'rsus',
      'port': 'ports',
      'warehouse': 'warehouses',
      'ca': 'cas'
    };
    
    const nodeTypeDir = nodeTypeMap[nodeType] || 'vehicles';
    
    // 🔥 关键修改：使用转换后的节点ID格式
    const convertedNodeId = convertNodeIdForFileName(nodeId);
    const messageFile = `${convertedNodeId}__messages.txt`;
    const messagePath = path.join(communicationsPath, nodeTypeDir, messageFile);
    
    console.log(`尝试读取通信消息: ${messagePath}`);
    
    if (!fsSync.existsSync(messagePath)) {
      console.log(`通信消息文件不存在: ${messagePath}`);
      return {
        hasMessages: false,
        totalMessages: 0,
        recentMessages: [],
        messageTypes: {},
        lastActivity: null
      };
    }

    const content = await fs.readFile(messagePath, 'utf8');
    const messages = parseMessagesContent(content);
    
    // 分析消息统计
    const messageTypes = {};
    messages.forEach(msg => {
      const type = msg.type || 'unknown';
      messageTypes[type] = (messageTypes[type] || 0) + 1;
    });

    // 获取最近的消息（最多50条）
    const recentMessages = messages
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 50);

    return {
      hasMessages: true,
      totalMessages: messages.length,
      recentMessages: recentMessages,
      messageTypes: messageTypes,
      lastActivity: messages.length > 0 ? messages[0].timestamp : null,
      filePath: messagePath
    };

  } catch (error) {
    console.error(`获取节点 ${nodeId} 通信消息失败:`, error);
    return {
      hasMessages: false,
      totalMessages: 0,
      recentMessages: [],
      messageTypes: {},
      lastActivity: null,
      error: error.message
    };
  }
}

/**
 * 🆕 新增：解析通信消息内容
 */
function parseMessagesContent(content) {
  const lines = content.split('\n').filter(line => line.trim());
  const messages = [];
  let currentMessage = null;
  
  for (const line of lines) {
    try {
      const trimmedLine = line.trim();
      
      // 跳过分隔线和标题行
      if (trimmedLine.startsWith('===') || trimmedLine.startsWith('---')) {
        continue;
      }
      
      // 检查是否是时间戳行
      if (trimmedLine.startsWith('Timestamp:')) {
        // 如果有之前的消息，先保存
        if (currentMessage) {
          messages.push({
            id: `msg_${currentMessage.timestamp}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date(parseInt(currentMessage.timestamp) * 1000).toISOString(),
            type: currentMessage.encryption || 'unknown',
            content: currentMessage.plaintext || currentMessage.sender || 'Communication message',
            sender: currentMessage.sender,
            receiver: currentMessage.receiver,
            encryption: currentMessage.encryption,
            signature: currentMessage.signature,
            raw: currentMessage.raw
          });
        }
        
        // 开始新消息
        currentMessage = {
          timestamp: trimmedLine.split('Timestamp:')[1].trim(),
          raw: trimmedLine
        };
      } else if (currentMessage) {
        // 解析其他字段
        if (trimmedLine.startsWith('Sender:')) {
          currentMessage.sender = trimmedLine.split('Sender:')[1].trim();
        } else if (trimmedLine.startsWith('Receiver:')) {
          currentMessage.receiver = trimmedLine.split('Receiver:')[1].trim();
        } else if (trimmedLine.startsWith('Encryption:')) {
          currentMessage.encryption = trimmedLine.split('Encryption:')[1].trim();
        } else if (trimmedLine.startsWith('Plaintext:')) {
          currentMessage.plaintext = trimmedLine.split('Plaintext:')[1].trim();
        } else if (trimmedLine.startsWith('Signature:')) {
          currentMessage.signature = trimmedLine.split('Signature:')[1].trim();
        }
        
        // 累积原始数据
        currentMessage.raw += '\n' + trimmedLine;
      }
    } catch (error) {
      console.error('解析消息行失败:', line, error);
    }
  }
  
  // 处理最后一条消息
  if (currentMessage) {
    messages.push({
      id: `msg_${currentMessage.timestamp}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(parseInt(currentMessage.timestamp) * 1000).toISOString(),
      type: currentMessage.encryption || 'unknown',
      content: currentMessage.plaintext || currentMessage.sender || 'Communication message',
      sender: currentMessage.sender,
      receiver: currentMessage.receiver,
      encryption: currentMessage.encryption,
      signature: currentMessage.signature,
      raw: currentMessage.raw
    });
  }
  
  return messages;
}
async function getNodeQCAInfo(nodeId) {
  try {
    const qcaStoragePath = path.join(__dirname, '../messages/qca_storage');
    
    const qcaInfo = {
      hasQuantumKey: false,
      hasSignatures: false,
      quantumKey: null,
      signatures: [],
      operationsLog: [],
      keyInfo: null,
      signatureCount: 0,
      lastSignature: null,
      lastOperation: null
    };

    // 🔍 检查量子密钥文件
    const keyFile = `node_${nodeId}_key.dat`;
    const keyPath = path.join(qcaStoragePath, 'keys', keyFile);
    
    console.log(`检查QCA密钥文件: ${keyPath}`);
    
    if (fsSync.existsSync(keyPath)) {
      qcaInfo.hasQuantumKey = true;
      qcaInfo.keyInfo = await parseQuantumKeyFile(keyPath, nodeId);
      console.log(`✅ 找到节点 ${nodeId} 的量子密钥`);
    }

    // 🔍 检查签名日志文件
    const signatureFile = `node_${nodeId}_signatures.log`;
    const signaturePath = path.join(qcaStoragePath, 'signatures', signatureFile);
    
    console.log(`检查QCA签名文件: ${signaturePath}`);
    
    if (fsSync.existsSync(signaturePath)) {
      qcaInfo.hasSignatures = true;
      qcaInfo.signatures = await parseSignatureLogFile(signaturePath);
      qcaInfo.signatureCount = qcaInfo.signatures.length;
      
      if (qcaInfo.signatures.length > 0) {
        qcaInfo.lastSignature = qcaInfo.signatures[0]; // 最新的签名
      }
      
      console.log(`✅ 找到节点 ${nodeId} 的 ${qcaInfo.signatureCount} 个签名记录`);
    }

    // 🔍 读取QCA操作日志
    const operationsLogPath = path.join(qcaStoragePath, 'logs', 'qca_operations.log');
    if (fsSync.existsSync(operationsLogPath)) {
      qcaInfo.operationsLog = await parseQCAOperationsLog(operationsLogPath, nodeId);
      
      if (qcaInfo.operationsLog.length > 0) {
        qcaInfo.lastOperation = qcaInfo.operationsLog[0];
      }
      
      console.log(`✅ 找到节点 ${nodeId} 的 ${qcaInfo.operationsLog.length} 条操作记录`);
    }

    return qcaInfo;

  } catch (error) {
    console.error(`获取节点 ${nodeId} QCA信息失败:`, error);
    return {
      hasQuantumKey: false,
      hasSignatures: false,
      quantumKey: null,
      signatures: [],
      operationsLog: [],
      keyInfo: null,
      signatureCount: 0,
      lastSignature: null,
      lastOperation: null,
      error: error.message
    };
  }
}

/**
 * 🆕 新增：解析量子密钥文件
 */
async function parseQuantumKeyFile(keyPath, nodeId) {
  try {
    const stats = await fs.stat(keyPath);
    const keyData = await fs.readFile(keyPath);
    
    // 分析密钥文件的基本信息
    const keyInfo = {
      fileName: path.basename(keyPath),
      fileSize: stats.size,
      createdTime: stats.birthtime.toISOString(),
      modifiedTime: stats.mtime.toISOString(),
      keyType: 'quantum',
      algorithm: 'BB84', // 默认算法
      keyLength: keyData.length,
      entropy: calculateEntropy(keyData),
      status: 'active',
      nodeId: nodeId
    };

    // 根据文件大小和内容推断密钥质量
    if (keyInfo.keyLength > 1024) {
      keyInfo.quality = 'high';
    } else if (keyInfo.keyLength > 512) {
      keyInfo.quality = 'medium';
    } else {
      keyInfo.quality = 'low';
    }

    // 模拟量子特性
    keyInfo.quantumProperties = {
      entanglement: Math.random() > 0.3,
      superposition: Math.random() > 0.4,
      coherenceTime: Math.floor(Math.random() * 1000) + 100, // 毫秒
      fidelity: (0.8 + Math.random() * 0.2).toFixed(3), // 0.8-1.0
      errorRate: (Math.random() * 0.05).toFixed(4) // 0-5%
    };

    return keyInfo;

  } catch (error) {
    console.error(`解析量子密钥文件失败 ${keyPath}:`, error);
    return null;
  }
}

/**
 * 🆕 新增：解析签名日志文件
 */
async function parseSignatureLogFile(signaturePath) {
  try {
    const content = await fs.readFile(signaturePath, 'utf8');
    const signatures = [];
    
    // 按记录分割
    const records = content.split('-----NEW SIGNATURE RECORD-----').slice(1);
    
    for (const record of records) {
      const lines = record.split('\n').filter(line => line.trim());
      const signature = {};
      
      for (const line of lines) {
        const trimmedLine = line.trim();
        
        if (trimmedLine.startsWith('Timestamp:')) {
          signature.timestamp = trimmedLine.split('Timestamp:')[1].trim();
        } else if (trimmedLine.startsWith('Node ID:')) {
          signature.nodeId = trimmedLine.split('Node ID:')[1].trim();
        } else if (trimmedLine.startsWith('Signed Data')) {
          signature.signedData = trimmedLine.split(':')[1].trim();
        } else if (trimmedLine.startsWith('Signature:')) {
          signature.signature = trimmedLine.split('Signature:')[1].trim();
        }
      }
      
      if (signature.timestamp && signature.signature) {
        // 添加额外信息
        signature.id = `sig_${signature.timestamp.replace(/[^\d]/g, '')}_${Math.random().toString(36).substr(2, 6)}`;
        signature.algorithm = 'QCA-SIG';
        signature.keyType = 'quantum';
        signature.verificationStatus = 'verified'; // 模拟验证状态
        
        signatures.push(signature);
      }
    }
    
    // 按时间戳排序（最新的在前）
    signatures.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    return signatures;

  } catch (error) {
    console.error(`解析签名日志文件失败 ${signaturePath}:`, error);
    return [];
  }
}

/**
 * 🆕 新增：解析QCA操作日志
 */
async function parseQCAOperationsLog(operationsLogPath, nodeId) {
  try {
    const content = await fs.readFile(operationsLogPath, 'utf8');
    const operations = [];
    const lines = content.split('\n');
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine) continue;
      
      // 检查是否与当前节点相关
      if (trimmedLine.includes(nodeId) || trimmedLine.includes('global')) {
        const operation = {
          id: `op_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
          timestamp: new Date().toISOString(), // 默认时间戳
          type: 'operation',
          message: trimmedLine,
          nodeId: nodeId,
          raw: trimmedLine
        };
        
        // 尝试提取时间戳
        const timestampMatch = trimmedLine.match(/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/);
        if (timestampMatch) {
          operation.timestamp = new Date(timestampMatch[0]).toISOString();
        }
        
        // 根据内容确定操作类型
        if (trimmedLine.includes('key')) {
          operation.operationType = 'key_management';
        } else if (trimmedLine.includes('signature') || trimmedLine.includes('sign')) {
          operation.operationType = 'signature';
        } else if (trimmedLine.includes('encrypt') || trimmedLine.includes('decrypt')) {
          operation.operationType = 'encryption';
        } else if (trimmedLine.includes('entangle')) {
          operation.operationType = 'entanglement';
        } else {
          operation.operationType = 'general';
        }
        
        operations.push(operation);
      }
    }
    
    // 按时间戳排序（最新的在前）
    operations.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    return operations.slice(0, 20); // 最多返回20条记录

  } catch (error) {
    console.error(`解析QCA操作日志失败 ${operationsLogPath}:`, error);
    return [];
  }
}

/**
 * 🆕 新增：计算数据熵值
 */
function calculateEntropy(data) {
  const frequency = {};
  
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    frequency[byte] = (frequency[byte] || 0) + 1;
  }
  
  let entropy = 0;
  const length = data.length;
  
  for (const freq of Object.values(frequency)) {
    const p = freq / length;
    entropy -= p * Math.log2(p);
  }
  
  return entropy.toFixed(3);
}

// 导出新增的函数
module.exports = {
  readLogFiles,
  startLogWatcher,
  LOG_PATHS,
  FILE_EXTENSIONS,
  generateMockLogs,
  getNodesInformation,
  getNodeDetails,
  getNodeCommunications,
  parseMessagesContent,
  convertNodeIdForFileName,
  // 🆕 新增QCA相关导出
  getNodeQCAInfo,
  parseQuantumKeyFile,
  parseSignatureLogFile,
  parseQCAOperationsLog,
  calculateEntropy
};