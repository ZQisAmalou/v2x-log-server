#!/bin/bash

echo "======================================"
echo "   Veins 日志监控服务器启动脚本"
echo "======================================"
echo

echo "检查 Node.js 版本..."
if ! command -v node &> /dev/null; then
    echo "错误: 未找到 Node.js，请先安装 Node.js 16+"
    exit 1
fi

node --version

echo
echo "检查依赖包..."
if [ ! -d "node_modules" ]; then
    echo "首次运行，正在安装依赖包..."
    npm install
    if [ $? -ne 0 ]; then
        echo "错误: 依赖包安装失败"
        exit 1
    fi
fi

echo
echo "创建必需目录..."
node scripts/create-directories.js

echo
echo "启动服务器..."
echo "服务器地址: http://localhost:5000"
echo "API端点: http://localhost:5000/api/logs"
echo "健康检查: http://localhost:5000/api/health"
echo
echo "按 Ctrl+C 停止服务器"
echo "======================================"

npm run dev