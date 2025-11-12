import express from 'express';
import connectDB from './config/db.js';
import User from './models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';

const app = express();
dotenv.config();

// Cấu hình CORS
app.use(cors({ origin: 'http://localhost:5173' }));

// Middleware phân tích yêu cầu JSON
app.use(express.json());

// Kết nối database
connectDB();

// Cổng chạy server
const PORT = process.env.PORT || 5009;

// Middleware xác thực JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Không có token, bạn không được phép truy cập" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: err.name === 'TokenExpiredError' ? "Token đã hết hạn, vui lòng đăng nhập lại." : "Token không hợp lệ" });
    }
    req.user = decoded; // Lưu thông tin user vào request
    next();
  });
};


// Route đăng ký
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email đã được đăng ký' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      createdAt: new Date()  // Lưu ngày tạo tài khoản
    });
    await newUser.save();

    res.status(201).json({
      username: newUser.username,
      email: newUser.email,
      createdAt: newUser.createdAt  // Trả về ngày tạo tài khoản
    });
  } catch (error) {
    console.error('Lỗi:', error);
    res.status(500).json({ error: 'Đăng ký thất bại' });
  }
});

// Route đăng nhập
app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin' });
  }

  try {
    // Lấy thông tin người dùng từ cơ sở dữ liệu
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Tài khoản không hợp lệ, vui lòng đăng ký tài khoản mới!' });
    }

    // Kiểm tra mật khẩu
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng!' });
    }

    // Tạo JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '8h' });

    // Kiểm tra xem giá trị của user.createdAt có tồn tại hay không
    console.log('User object:', user);  // Đảm bảo rằng `createdAt` có trong object

    // Trả về dữ liệu người dùng, bao gồm ngày tạo
    res.json({
      token,
      email: user.email,
      username: user.username,
      createdAt: user.createdAt,  // Đảm bảo trả về createdAt
    });
  } catch (error) {
    console.error('Lỗi đăng nhập:', error);
    res.status(500).json({ error: 'Lỗi máy chủ' });
  }
});

// Route đổi mật khẩu
app.post("/api/change-password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (newPassword.length < 8) {
    return res.status(400).json({ error: "Mật khẩu mới phải có ít nhất 8 ký tự." });
  }

  try {
    // Lấy thông tin user từ token
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "Tài khoản không tồn tại" });
    }

    // Kiểm tra mật khẩu hiện tại
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Mật khẩu hiện tại không đúng" });
    }

    // Hash mật khẩu mới và lưu lại
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Trả về thông báo thành công
    res.status(200).json({ message: "Mật khẩu đã được thay đổi thành công!" });
  } catch (error) {
    console.error("Lỗi đổi mật khẩu:", error);
    res.status(500).json({ error: "Lỗi máy chủ" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});