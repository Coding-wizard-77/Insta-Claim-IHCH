// Full-Stack ABHA Platform with Secure Medical Data Sharing

// BACKEND (server.js)
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const port = 5000;

app.use(cors());
app.use(bodyParser.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const otpStore = new Map();

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { username, email, password, abhaId } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, email, password, abha_id) VALUES ($1, $2, $3, $4) RETURNING id, username, email',
            [username, email, hashedPassword, abhaId]
        );
        res.status(201).json({ message: 'Registration successful', user: result.rows[0] });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user' });
    }
});

// OTP Handling
app.post('/send-otp', (req, res) => {
    const { email } = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore.set(email, otp);
    console.log(`OTP for ${email}: ${otp}`);
    res.json({ message: 'OTP sent successfully' });
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!otpStore.has(email) || otpStore.get(email) !== otp) return res.status(400).json({ message: 'Invalid OTP' });
    otpStore.delete(email);
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ message: 'User not found' });
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, user });
});

// Chat System
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    socket.on('message', (message) => io.emit('message', message));
    socket.on('disconnect', () => console.log('User disconnected:', socket.id));
});

// File Upload
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    res.json({ message: 'File uploaded successfully' });
});

server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

