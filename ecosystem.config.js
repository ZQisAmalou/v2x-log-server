module.exports = {
  apps: [
    {
      name: 'veins-log-server',
      script: './server.js',
      instances: 1, // 单实例，因为需要共享WebSocket连接状态
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'development',
        PORT: 5000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 5000
      },
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      time: true,
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 5000,
      kill_timeout: 5000,
      listen_timeout: 10000,
      shutdown_with_message: true
    }
  ],
  
  deploy: {
    production: {
      user: 'deploy',
      host: 'your-server.com',
      ref: 'origin/main',
      repo: 'https://github.com/your-username/veins-log-monitor.git',
      path: '/var/www/veins-log-monitor',
      'post-deploy': 'cd server && npm install && pm2 reload ecosystem.config.js --env production'
    }
  }
};