const express = require('express');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const ENCRYPT_SECRET = process.env.ENCRYPT_SECRET || 'car_plate_encrypt_key_2024';
function encryptPlate(plateNumber) {
  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(ENCRYPT_SECRET, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(plateNumber, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('加密失败:', error);
    return null;
  }
}

function decryptPlate(encryptedPlate) {
  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(ENCRYPT_SECRET, 'salt', 32);
    const parts = encryptedPlate.split(':');
    if (parts.length !== 2) {
      throw new Error('无效的加密格式');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('解密失败:', error);
    return null;
  }
}
const DATA_DIR = path.join(__dirname, 'data');
const PLATES_FILE = path.join(DATA_DIR, 'plates.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
function initDataFiles() {
  if (!fs.existsSync(PLATES_FILE)) {
    fs.writeFileSync(PLATES_FILE, JSON.stringify([], null, 2));
  }
  if (!fs.existsSync(SETTINGS_FILE)) {
    const defaultSettings = {
      app_token: '',
      admin_username: process.env.ADMIN_USERNAME || 'admin',
      admin_password: process.env.ADMIN_PASSWORD || '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' // password
    };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(defaultSettings, null, 2));
  }
  if (!fs.existsSync(LOGS_FILE)) {
    fs.writeFileSync(LOGS_FILE, JSON.stringify([], null, 2));
  }
}
function readJsonFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`读取文件错误 ${filePath}:`, error);
    return null;
  }
}
function writeJsonFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`写入文件错误 ${filePath}:`, error);
    return false;
  }
}
function addLog(action, details, ip) {
  const logs = readJsonFile(LOGS_FILE) || [];
  const log = {
    id: uuidv4(),
    action,
    details,
    ip,
    created_at: new Date().toISOString()
  };
  logs.unshift(log); 
  if (logs.length > 1000) {
    logs.splice(1000);
  }
  
  writeJsonFile(LOGS_FILE, logs);
}
initDataFiles();
app.use(express.json());
app.use(express.static('admin'));
app.use(express.static('.'));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: '登录尝试次数过多，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});
const notifyLimiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 20,
  message: { error: '通知发送过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    return req.body && req.body.message === '__VALIDATION_CHECK__';
  }
});
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '未提供访问令牌' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '访问令牌无效或已过期' });
    }
    req.user = user;
    next();
  });
}
app.get('/notify', (req, res) => {
  res.sendFile(path.join(__dirname, 'notify.html'));
});
app.post('/api/encrypt-plate-demo', (req, res) => {
  try {
    const { plate } = req.body;
    
    if (!plate) {
      return res.status(400).json({ error: '车牌号不能为空' });
    }
    
    const encryptedPlate = encryptPlate(plate);
    if (!encryptedPlate) {
      return res.status(500).json({ error: '车牌加密失败' });
    }
    
    const encryptedUrl = `${req.protocol}://${req.get('host')}/notify?token=${encryptedPlate}`;
    
    res.json({ 
      success: true, 
      encryptedUrl,
      originalPlate: plate
    });
  } catch (error) {
    console.error('生成加密URL失败:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.post('/api/encrypt-plate', authenticateToken, (req, res) => {
  try {
    const { plate } = req.body;
    
    if (!plate) {
      return res.status(400).json({ error: '车牌号不能为空' });
    }
    
    const encryptedPlate = encryptPlate(plate);
    if (!encryptedPlate) {
      return res.status(500).json({ error: '车牌加密失败' });
    }
    
    const encryptedUrl = `${req.protocol}://${req.get('host')}/notify?token=${encryptedPlate}`;
    
    res.json({ 
      success: true, 
      encryptedUrl,
      originalPlate: plate
    });
  } catch (error) {
    console.error('生成加密URL失败:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.post('/api/decrypt-plate', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: '加密token不能为空' });
    }
    
    const decryptedPlate = decryptPlate(token);
    if (!decryptedPlate) {
      return res.status(400).json({ error: '无效的加密token' });
    }
    
    res.json({ 
      success: true, 
      plate: decryptedPlate
    });
  } catch (error) {
    console.error('解密车牌失败:', error);
    res.status(400).json({ error: '解密失败' });
  }
});
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    const settings = readJsonFile(SETTINGS_FILE);
    if (!settings) {
      return res.status(500).json({ error: '系统配置读取失败' });
    }

    if (username !== settings.admin_username) {
      addLog('登录失败', `用户名错误: ${username}`, req.ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const isValidPassword = await bcrypt.compare(password, settings.admin_password);
    if (!isValidPassword) {
      addLog('登录失败', `密码错误: ${username}`, req.ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const token = jwt.sign(
      { username: settings.admin_username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    addLog('登录成功', `管理员登录: ${username}`, req.ip);
    res.json({ token, message: '登录成功' });
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.get('/api/plates', authenticateToken, (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const allPlates = readJsonFile(PLATES_FILE) || [];
    let filteredPlates = allPlates;
    if (search) {
      filteredPlates = allPlates.filter(plate => 
        plate.plate.toLowerCase().includes(search.toLowerCase()) ||
        plate.remark.toLowerCase().includes(search.toLowerCase())
      );
    }
    const total = filteredPlates.length;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const plates = filteredPlates.slice(startIndex, endIndex);
    res.json({
      plates,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('获取车牌列表错误:', error);
    res.status(500).json({ error: '获取车牌列表失败' });
  }
});
app.post('/api/plates', authenticateToken, (req, res) => {
  try {
    const { plate, uids, remark } = req.body;
    
    if (!plate || !uids) {
      return res.status(400).json({ error: '车牌号和用户UID不能为空' });
    }

    const plates = readJsonFile(PLATES_FILE) || [];
    if (plates.find(p => p.plate === plate.toUpperCase())) {
      return res.status(400).json({ error: '车牌号已存在' });
    }
    const uidsArray = Array.isArray(uids) ? uids : (typeof uids === 'string' ? uids.split(',').map(uid => uid.trim()).filter(uid => uid) : []);
    
    const newPlate = {
      id: uuidv4(),
      plate: plate.toUpperCase(),
      uids: uidsArray,
      remark: remark || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    plates.push(newPlate);
    
    if (writeJsonFile(PLATES_FILE, plates)) {
      addLog('添加车牌', `车牌: ${newPlate.plate}`, req.ip);
      res.json({ message: '车牌添加成功', plate: newPlate });
    } else {
      res.status(500).json({ error: '车牌添加失败' });
    }
  } catch (error) {
    console.error('添加车牌错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.put('/api/plates/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const { plate, uids, remark } = req.body;
    
    if (!plate || !uids) {
      return res.status(400).json({ error: '车牌号和用户UID不能为空' });
    }

    const plates = readJsonFile(PLATES_FILE) || [];
    const plateIndex = plates.findIndex(p => p.id === id);
    
    if (plateIndex === -1) {
      return res.status(404).json({ error: '车牌不存在' });
    }
    const existingPlate = plates.find(p => p.plate === plate.toUpperCase() && p.id !== id);
    if (existingPlate) {
      return res.status(400).json({ error: '车牌号已存在' });
    }
    const uidsArray = Array.isArray(uids) ? uids : (typeof uids === 'string' ? uids.split(',').map(uid => uid.trim()).filter(uid => uid) : []);
    
    plates[plateIndex] = {
      ...plates[plateIndex],
      plate: plate.toUpperCase(),
      uids: uidsArray,
      remark: remark || '',
      updated_at: new Date().toISOString()
    };

    if (writeJsonFile(PLATES_FILE, plates)) {
      addLog('更新车牌', `车牌: ${plates[plateIndex].plate}`, req.ip);
      res.json({ message: '车牌更新成功', plate: plates[plateIndex] });
    } else {
      res.status(500).json({ error: '车牌更新失败' });
    }
  } catch (error) {
    console.error('更新车牌错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.delete('/api/plates/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    
    const plates = readJsonFile(PLATES_FILE) || [];
    const plateIndex = plates.findIndex(p => p.id === id);
    
    if (plateIndex === -1) {
      return res.status(404).json({ error: '车牌不存在' });
    }

    const deletedPlate = plates[plateIndex];
    plates.splice(plateIndex, 1);

    if (writeJsonFile(PLATES_FILE, plates)) {
      addLog('删除车牌', `车牌: ${deletedPlate.plate}`, req.ip);
      res.json({ message: '车牌删除成功' });
    } else {
      res.status(500).json({ error: '车牌删除失败' });
    }
  } catch (error) {
    console.error('删除车牌错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.get('/api/settings', authenticateToken, (req, res) => {
  try {
    const settings = readJsonFile(SETTINGS_FILE);
    if (settings) {
      const { admin_password, ...safeSettings } = settings;
      res.json(safeSettings);
    } else {
      res.status(500).json({ error: '获取设置失败' });
    }
  } catch (error) {
    console.error('获取设置错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.get('/api/app-token', authenticateToken, (req, res) => {
  try {
    const settings = readJsonFile(SETTINGS_FILE);
    if (settings) {
      res.json({ token: settings.app_token || '' });
    } else {
      res.status(500).json({ error: '获取APP Token失败' });
    }
  } catch (error) {
    console.error('获取APP Token错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.post('/api/app-token', authenticateToken, (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'APP Token不能为空' });
    }

    const settings = readJsonFile(SETTINGS_FILE);
    if (!settings) {
      return res.status(500).json({ error: '读取设置失败' });
    }

    settings.app_token = token;
    
    if (writeJsonFile(SETTINGS_FILE, settings)) {
      addLog('更新APP Token', 'APP Token已更新', req.ip);
      res.json({ message: 'APP Token更新成功' });
    } else {
      res.status(500).json({ error: 'APP Token更新失败' });
    }
  } catch (error) {
    console.error('更新APP Token错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.put('/api/settings/app-token', authenticateToken, (req, res) => {
  try {
    const { app_token } = req.body;
    
    if (!app_token) {
      return res.status(400).json({ error: 'APP Token不能为空' });
    }

    const settings = readJsonFile(SETTINGS_FILE);
    if (!settings) {
      return res.status(500).json({ error: '读取设置失败' });
    }

    settings.app_token = app_token;
    
    if (writeJsonFile(SETTINGS_FILE, settings)) {
      addLog('更新APP Token', 'APP Token已更新', req.ip);
      res.json({ message: 'APP Token更新成功' });
    } else {
      res.status(500).json({ error: 'APP Token更新失败' });
    }
  } catch (error) {
    console.error('更新APP Token错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});
app.post('/api/notify', notifyLimiter, async (req, res) => {
  try {
    const { plate, message } = req.body;
    
    if (!plate) {
      return res.status(400).json({ error: '车牌号不能为空' });
    }

    const plates = readJsonFile(PLATES_FILE) || [];
    const plateInfo = plates.find(p => p.plate === plate.toUpperCase());
    
    if (!plateInfo) {
      if (message !== '__VALIDATION_CHECK__') {
        addLog('通知失败', `车牌不存在: ${plate}`, req.ip);
      }
      return res.status(404).json({ error: '车牌号不存在，请联系管理员添加' });
    }
    if (message === '__VALIDATION_CHECK__') {
      return res.json({ message: '车牌验证成功', plate: plateInfo.plate });
    }

    const settings = readJsonFile(SETTINGS_FILE);
    if (!settings || !settings.app_token) {
      addLog('通知失败', `APP Token未配置: ${plate}`, req.ip);
      return res.status(500).json({ error: 'APP Token未配置，请联系管理员' });
    }
    const { remark } = plateInfo;
    
    // 生成HTML格式的通知内容
    const currentTime = new Date().toLocaleString('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    
    let htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; background: #f8f9fa; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
        <h2 style="margin: 0; font-size: 18px;">🚗 挪车通知</h2>
      </div>
      
      <div style="padding: 20px; background: white;">
        <div style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 4px;">
          <div style="font-weight: bold; color: #1976d2; margin-bottom: 5px;">车牌号码</div>
          <div style="font-size: 16px; font-weight: bold; color: #333;">${plateInfo.plate}</div>
        </div>
        
        ${remark ? `
        <div style="margin-bottom: 15px; padding: 12px; background: #f3e5f5; border-left: 4px solid #9c27b0; border-radius: 4px;">
          <div style="font-weight: bold; color: #7b1fa2; margin-bottom: 5px;">车辆备注</div>
          <div style="color: #333;">${remark}</div>
        </div>
        ` : ''}
        
        ${message && message.trim() ? `
        <div style="margin-bottom: 15px; padding: 12px; background: #fff3e0; border-left: 4px solid #ff9800; border-radius: 4px;">
          <div style="font-weight: bold; color: #f57c00; margin-bottom: 5px;">📝 留言内容</div>
          <div style="color: #333; line-height: 1.4;">${message.trim()}</div>
        </div>
        ` : ''}
        
        <div style="margin-bottom: 15px; padding: 12px; background: #ffebee; border-left: 4px solid #f44336; border-radius: 4px;">
          <div style="font-weight: bold; color: #d32f2f; margin-bottom: 5px;">⚠️ 紧急提醒</div>
          <div style="color: #333;">请您尽快移动车辆，避免影响他人通行</div>
        </div>
        
        <div style="text-align: center; padding: 15px 0; border-top: 1px solid #eee; margin-top: 15px;">
          <div style="color: #666; font-size: 12px;">通知时间：${currentTime}</div>
          <div style="color: #666; font-size: 12px;">来源IP：${req.ip}</div>
        </div>
      </div>
    </div>
    `;
    
    try {
      const response = await fetch('https://wxpusher.zjiecode.com/api/send/message', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          appToken: settings.app_token,
          content: htmlContent,
          summary: `🚗 挪车通知 - ${plateInfo.plate}`,
          contentType: 2,
          uids: plateInfo.uids
        })
      });
      const result = await response.json();     
      if (result.success) {
        addLog('发送通知', `车牌: ${plateInfo.plate}, 用户: ${plateInfo.uids.join(',')}`, req.ip);
        res.json({ 
          message: '通知发送成功',
          plate: plateInfo.plate,
          sent_to: plateInfo.uids.length
        });
      } else {
        addLog('通知失败', `WxPusher错误: ${result.msg}, 车牌: ${plateInfo.plate}`, req.ip);
        res.status(500).json({ error: `通知发送失败: ${result.msg}` });
      }
    } catch (fetchError) {
      console.error('WxPusher API调用错误:', fetchError);
      addLog('通知失败', `网络错误: ${fetchError.message}, 车牌: ${plateInfo.plate}`, req.ip);
      res.status(500).json({ error: '通知发送失败，网络错误' });
    }
  } catch (error) {
    console.error('发送通知错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
})
app.get('/api/logs', authenticateToken, (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const logs = readJsonFile(LOGS_FILE) || [];
    let filteredLogs = logs;
    if (search) {
      filteredLogs = logs.filter(log => 
        log.action.includes(search) || 
        log.details.includes(search) ||
        log.ip.includes(search)
      );
    }
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedLogs = filteredLogs.slice(startIndex, endIndex);  
    res.json({
      logs: paginatedLogs,
      pagination: {
        total: filteredLogs.length,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(filteredLogs.length / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('获取日志错误:', error);
    res.status(500).json({ error: '获取日志失败' });
  }
});
app.listen(PORT, () => {
  console.log(`🚀 车辆通知系统启动成功`);
  console.log(`📱 管理界面: http://localhost:${PORT}/login.html`);
  console.log(`🔗 挪车页面: http://localhost:${PORT}/notify`);
  console.log(`⚙️  端口: ${PORT}`);
});
process.on('SIGINT', () => {
  console.log('\n 正在关闭服务器...');
  process.exit(0);
});
process.on('SIGTERM', () => {
  console.log('\n 正在关闭服务器...');
  process.exit(0);
});