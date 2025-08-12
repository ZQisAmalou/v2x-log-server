@echo off
echo ======================================
echo    Veins 日志监控服务器启动脚本
echo ======================================
echo.

echo 检查 Node.js 版本...
node --version
if %errorlevel% neq 0 (
    echo 错误: 未找到 Node.js，请先安装 Node.js 16+
    pause
    exit /b 1
)

echo.
echo 检查依赖包...
if not exist "node_modules" (
    echo 首次运行，正在安装依赖包...
    npm install
    if %errorlevel% neq 0 (
        echo 错误: 依赖包安装失败
        pause
        exit /b 1
    )
)

echo.
echo 创建必需目录...
node scripts/create-directories.js

echo.
echo 启动服务器...
echo 服务器地址: http://localhost:5000
echo API端点: http://localhost:5000/api/logs
echo 健康检查: http://localhost:5000/api/health
echo.
echo 按 Ctrl+C 停止服务器
echo ======================================

npm run dev