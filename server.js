// =============================================================================
// || CHALO RIDE-SHARING APPLICATION - FINAL & COMPLETE SERVER                ||
// =============================================================================

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const crypto = require('crypto');
// **FIX:** The 'node-fetch' import is removed as it's built-in in modern Node.js

// --- Basic Setup ---
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// =============================================================================
// || MIDDLEWARE & CONFIGURATION                                              ||
// =============================================================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws://localhost:3000", "https://nominatim.openstreetmap.org"], // Allow connection to geocoding API
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.static('public'));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { message: 'Too many requests from this IP, please try again later.' }
});
app.use(generalLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your_super_secret_refresh_key';
const dbConfig = { host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root', password: process.env.DB_PASSWORD || 'Datta@2006', database: process.env.DB_NAME || 'chalo_db', connectionLimit: 15 };
let pool;

// =============================================================================
// || DATABASE & UTILITIES                                                    ||
// =============================================================================

async function initDatabase() {
  try {
    const tempPool = mysql.createPool({ ...dbConfig, database: null });
    await tempPool.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
    await tempPool.end();
    pool = mysql.createPool(dbConfig);
    await createTables();
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    process.exit(1);
  }
}

async function createTables() {
    const queries = [
        `CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, phone VARCHAR(20), is_driver BOOLEAN DEFAULT FALSE, is_verified BOOLEAN DEFAULT FALSE, verification_token VARCHAR(255), rating DECIMAL(3,2) DEFAULT 5.00, total_ratings INT DEFAULT 0, total_trips INT DEFAULT 0, date_of_birth DATE, gender ENUM('male', 'female', 'other'), is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`,
        `CREATE TABLE IF NOT EXISTS trips (id INT AUTO_INCREMENT PRIMARY KEY, driver_id INT NOT NULL, origin VARCHAR(255) NOT NULL, destination VARCHAR(255) NOT NULL, origin_lat DECIMAL(10, 8), origin_lng DECIMAL(11, 8), destination_lat DECIMAL(10, 8), destination_lng DECIMAL(11, 8), departure_date DATE NOT NULL, departure_time TIME NOT NULL, available_seats INT NOT NULL, booked_seats INT DEFAULT 0, suggested_fare DECIMAL(10, 2) NOT NULL, vehicle_info VARCHAR(255), smoking_allowed BOOLEAN DEFAULT FALSE, pets_allowed BOOLEAN DEFAULT FALSE, luggage_allowed BOOLEAN DEFAULT TRUE, status ENUM('active', 'started', 'completed', 'cancelled') DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (driver_id) REFERENCES users(id) ON DELETE CASCADE)`,
        `CREATE TABLE IF NOT EXISTS ride_requests (id INT AUTO_INCREMENT PRIMARY KEY, trip_id INT NOT NULL, passenger_id INT NOT NULL, status ENUM('pending', 'accepted', 'declined', 'completed', 'cancelled', 'no_show') DEFAULT 'pending', message TEXT, requested_seats INT DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (trip_id) REFERENCES trips(id) ON DELETE CASCADE, FOREIGN KEY (passenger_id) REFERENCES users(id) ON DELETE CASCADE, UNIQUE KEY unique_trip_passenger (trip_id, passenger_id))`,
        `CREATE TABLE IF NOT EXISTS chat_messages (id INT AUTO_INCREMENT PRIMARY KEY, request_id INT NOT NULL, sender_id INT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (request_id) REFERENCES ride_requests(id) ON DELETE CASCADE, FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE)`,
        `CREATE TABLE IF NOT EXISTS notifications (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, title VARCHAR(255) NOT NULL, message TEXT NOT NULL, type ENUM('trip_request', 'request_accepted', 'request_declined', 'trip_started', 'trip_completed', 'system', 'message') NOT NULL, is_read BOOLEAN DEFAULT FALSE, related_id INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
    ];
    for (const query of queries) await pool.execute(query);
}

async function geocode(locationName) {
    if (!locationName) return null;
    try {
        const response = await fetch(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(locationName)}&format=json&limit=1&countrycodes=in`);
        const data = await response.json();
        if (data && data.length > 0) {
            return {
                lat: parseFloat(data[0].lat),
                lng: parseFloat(data[0].lon)
            };
        }
        return null;
    } catch (error) {
        console.error("Geocoding error:", error);
        return null;
    }
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function checkDriverRole(req, res, next) {
  if (!req.user.is_driver) return res.status(403).json({ message: 'Forbidden: Drivers only' });
  next();
}

// =============================================================================
// || API ROUTES                                                              ||
// =============================================================================

app.post('/api/register', async (req, res) => {
  const { name, email, password, phone, is_driver, dateOfBirth, gender } = req.body;
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [existing] = await connection.execute('SELECT id FROM users WHERE email = ? FOR UPDATE', [email]);
    if (existing.length > 0) {
      await connection.rollback();
      return res.status(409).json({ message: 'An account with this email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    await connection.execute(`INSERT INTO users (name, email, password, phone, is_driver, date_of_birth, gender, verification_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [name, email, hashedPassword, phone, !!is_driver, dateOfBirth || null, gender || null, verificationToken]);
    await connection.commit();
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/verify-email/${verificationToken}`;
    console.log(`\n📧 DEV MODE: Verify user with this link: ${verificationUrl}\n`);
    res.status(201).json({ message: 'Registration successful. Please check server console to verify.' });
  } catch (error) {
    await connection.rollback();
    res.status(500).json({ message: 'Server error during registration' });
  } finally {
    connection.release();
  }
});

app.get('/api/verify-email/:token', async (req, res) => {
    const [result] = await pool.execute('UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = ?', [req.params.token]);
    if (result.affectedRows === 0) return res.status(400).send('<h1>Invalid or Expired Token</h1>');
    res.send('<h1>Email Verified!</h1><p>Your account is now active. You can log in.</p>');
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const [users] = await pool.execute('SELECT id, name, password, is_driver, is_verified, is_active FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
    const user = users[0];
    if (!user.is_active) return res.status(403).json({ message: 'This account has been deactivated.' });
    if (!user.is_verified) return res.status(403).json({ message: 'Please verify your email before logging in.' });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Invalid credentials' });
    const userPayload = { id: user.id, name: user.name, is_driver: user.is_driver };
    const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
    res.json({ accessToken, refreshToken, user: userPayload });
});

app.get('/api/profile', authenticateToken, async (req, res) => {
    const [users] = await pool.execute('SELECT id, name, email, phone, rating, total_ratings, total_trips, is_driver FROM users WHERE id = ?', [req.user.id]);
    res.json(users[0]);
});

app.post('/api/trips', authenticateToken, checkDriverRole, async (req, res) => {
    const { origin, destination, departureDate, departureTime, availableSeats, suggestedFare, vehicle_info, smoking_allowed, pets_allowed, luggage_allowed } = req.body;
    const originCoords = await geocode(origin);
    const destCoords = await geocode(destination);
    if (!originCoords || !destCoords) {
        return res.status(400).json({ message: "Could not find coordinates for the specified locations. Please be more specific." });
    }
    await pool.execute(`INSERT INTO trips (driver_id, origin, destination, origin_lat, origin_lng, destination_lat, destination_lng, departure_date, departure_time, available_seats, suggested_fare, vehicle_info, smoking_allowed, pets_allowed, luggage_allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.user.id, origin, destination, originCoords.lat, originCoords.lng, destCoords.lat, destCoords.lng, departureDate, departureTime, availableSeats, suggestedFare, vehicle_info || null, !!smoking_allowed, !!pets_allowed, !!luggage_allowed]);
    res.status(201).json({ message: 'Trip created successfully' });
});

app.get('/api/trips/search', async (req, res) => {
    try {
        const { origin, destination, departureDate, page = 1, limit = 20 } = req.query;
        const finalLimit = parseInt(limit, 10) || 20;
        const finalOffset = (parseInt(page, 10) - 1) * finalLimit || 0;

        let whereClauses = [`t.status = 'active'`, `t.departure_date >= CURDATE()`];
        let params = [];
        
        const originQuery = origin?.toLowerCase().trim();
        const destinationQuery = destination?.toLowerCase().trim();

        const originCoords = await geocode(originQuery);
        const destCoords = await geocode(destinationQuery);

        if (originCoords) {
            whereClauses.push(`(6371 * acos(cos(radians(?)) * cos(radians(t.origin_lat)) * cos(radians(t.origin_lng) - radians(?)) + sin(radians(?)) * sin(radians(t.origin_lat)))) <= 50`);
            params.push(originCoords.lat, originCoords.lng, originCoords.lat);
        } else if (originQuery) {
            whereClauses.push(`LOWER(t.origin) LIKE ?`);
            params.push(`%${originQuery}%`);
        }

        if (destCoords) {
            whereClauses.push(`(6371 * acos(cos(radians(?)) * cos(radians(t.destination_lat)) * cos(radians(t.destination_lng) - radians(?)) + sin(radians(?)) * sin(radians(t.destination_lat)))) <= 50`);
            params.push(destCoords.lat, destCoords.lng, destCoords.lat);
        } else if (destinationQuery) {
            whereClauses.push(`LOWER(t.destination) LIKE ?`);
            params.push(`%${destinationQuery}%`);
        }
        
        if (departureDate) {
            whereClauses.push(`t.departure_date = ?`);
            params.push(departureDate);
        }

        const whereSql = whereClauses.join(' AND ');
        
        const countQuery = `SELECT COUNT(*) as total FROM trips t WHERE ${whereSql}`;
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;

        const mainQuery = `SELECT t.*, u.name as driver_name, u.rating as driver_rating FROM trips t JOIN users u ON t.driver_id = u.id WHERE ${whereSql} ORDER BY t.departure_date, t.departure_time LIMIT ${finalLimit} OFFSET ${finalOffset}`;
        const [trips] = await pool.execute(mainQuery, params);

        res.json({ trips });
    } catch (error) {
        console.error('Search trips error:', error);
        res.status(500).json({ message: 'Failed to search trips' });
    }
});

app.get('/api/my-trips', authenticateToken, async (req, res) => {
    const { role } = req.query;
    if (role === 'driver') {
        const [trips] = await pool.execute(`SELECT * FROM trips WHERE driver_id = ? ORDER BY departure_date DESC`, [req.user.id]);
        res.json({ trips });
    } else if (role === 'passenger') {
        const [requests] = await pool.execute(`SELECT rr.id as request_id, rr.status as request_status, t.* FROM ride_requests rr JOIN trips t ON rr.trip_id = t.id WHERE rr.passenger_id = ? ORDER BY t.departure_date DESC`, [req.user.id]);
        res.json({ trips: requests });
    }
});

app.get('/api/ride-requests/driver', authenticateToken, checkDriverRole, async (req, res) => {
    const [requests] = await pool.execute(`SELECT rr.*, u.name as passenger_name FROM ride_requests rr JOIN users u ON rr.passenger_id = u.id JOIN trips t ON rr.trip_id = t.id WHERE t.driver_id = ? AND rr.status = 'pending'`, [req.user.id]);
    res.json({ requests });
});

app.get('/api/ride-requests/:id', authenticateToken, async (req, res) => {
    const [requests] = await pool.execute(`
        SELECT 
            rr.id, rr.status, rr.requested_seats,
            t.origin, t.destination, t.departure_date, t.departure_time, t.vehicle_info,
            p.id as passenger_id, p.name as passenger_name, p.rating as passenger_rating,
            d.id as driver_id, d.name as driver_name, d.rating as driver_rating
        FROM ride_requests rr
        JOIN trips t ON rr.trip_id = t.id
        JOIN users p ON rr.passenger_id = p.id
        JOIN users d ON t.driver_id = d.id
        WHERE rr.id = ?
    `, [req.params.id]);

    if (requests.length === 0) return res.status(404).json({ message: 'Ride request not found' });
    
    const request = requests[0];
    if (req.user.id !== request.passenger_id && req.user.id !== request.driver_id) {
        return res.status(403).json({ message: 'Forbidden' });
    }

    res.json(request);
});

app.get('/api/trips/:id/management', authenticateToken, checkDriverRole, async (req, res) => {
    const tripId = req.params.id;
    const driverId = req.user.id;
    const [trips] = await pool.execute('SELECT * FROM trips WHERE id = ? AND driver_id = ?', [tripId, driverId]);
    if (trips.length === 0) return res.status(404).json({ message: 'Trip not found or you are not the driver.' });
    const [pendingRequests] = await pool.execute(`SELECT rr.id, rr.requested_seats, u.name as passenger_name, u.rating as passenger_rating FROM ride_requests rr JOIN users u ON rr.passenger_id = u.id WHERE rr.trip_id = ? AND rr.status = 'pending'`, [tripId]);
    const [acceptedPassengers] = await pool.execute(`SELECT rr.id, rr.requested_seats, u.name as passenger_name, u.rating as passenger_rating FROM ride_requests rr JOIN users u ON rr.passenger_id = u.id WHERE rr.trip_id = ? AND rr.status = 'accepted'`, [tripId]);
    res.json({ tripDetails: trips[0], pendingRequests, acceptedPassengers });
});

app.post('/api/ride-requests', authenticateToken, async (req, res) => {
    const { tripId, requestedSeats, message } = req.body;
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [trips] = await connection.execute('SELECT * FROM trips WHERE id = ? FOR UPDATE', [tripId]);
        if (trips.length === 0) throw new Error('Trip not found');
        const trip = trips[0];
        if (trip.driver_id === req.user.id) throw new Error("You cannot request your own trip.");
        if (trip.status !== 'active') throw new Error("This trip is no longer active.");
        if ((trip.available_seats - trip.booked_seats) < requestedSeats) throw new Error("Not enough seats available.");
        const [result] = await connection.execute('INSERT INTO ride_requests (trip_id, passenger_id, requested_seats, message) VALUES (?, ?, ?, ?)', [tripId, req.user.id, requestedSeats, message || null]);
        await connection.commit();
        res.status(201).json({ message: 'Ride request sent successfully', requestId: result.insertId });
    } catch (error) {
        await connection.rollback();
        res.status(400).json({ message: error.message });
    } finally {
        connection.release();
    }
});

app.put('/api/ride-requests/:id/status', authenticateToken, checkDriverRole, async (req, res) => {
    const { status } = req.body;
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [requests] = await connection.execute(`SELECT rr.*, t.driver_id, t.available_seats, t.booked_seats FROM ride_requests rr JOIN trips t ON rr.trip_id = t.id WHERE rr.id = ? FOR UPDATE`, [req.params.id]);
        if (requests.length === 0) throw new Error('Request not found');
        const request = requests[0];
        if (request.driver_id !== req.user.id) throw new Error('Not authorized.');
        if (request.status !== 'pending') throw new Error('Request already processed.');
        if (status === 'accepted') {
            if ((request.available_seats - request.booked_seats) < request.requested_seats) throw new Error('Not enough seats.');
            await connection.execute('UPDATE trips SET booked_seats = booked_seats + ? WHERE id = ?', [request.requested_seats, request.trip_id]);
        }
        await connection.execute('UPDATE ride_requests SET status = ? WHERE id = ?', [status, req.params.id]);
        await connection.commit();
        res.json({ message: `Request ${status}` });
    } catch (error) {
        await connection.rollback();
        res.status(400).json({ message: error.message });
    } finally {
        connection.release();
    }
});

app.put('/api/trips/:id/start', authenticateToken, checkDriverRole, async (req, res) => {
    const [result] = await pool.execute(`UPDATE trips SET status = 'started' WHERE id = ? AND driver_id = ? AND status = 'active'`, [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(400).json({ message: 'Trip could not be started.' });
    res.json({ message: 'Trip started successfully' });
});

app.put('/api/trips/:id/complete', authenticateToken, checkDriverRole, async (req, res) => {
    const [result] = await pool.execute(`UPDATE trips SET status = 'completed' WHERE id = ? AND driver_id = ? AND status = 'started'`, [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(400).json({ message: 'Trip could not be completed.' });
    res.json({ message: 'Trip completed successfully' });
});

app.get('/api/chat/:requestId', authenticateToken, async (req, res) => {
    const [requests] = await pool.execute(`SELECT t.driver_id, rr.passenger_id FROM ride_requests rr JOIN trips t ON rr.trip_id = t.id WHERE rr.id = ?`, [req.params.requestId]);
    if (requests.length === 0 || (req.user.id !== requests[0].driver_id && req.user.id !== requests[0].passenger_id)) return res.status(403).json({ message: 'Forbidden' });
    const [messages] = await pool.execute(`SELECT cm.*, u.name as sender_name FROM chat_messages cm JOIN users u ON cm.sender_id = u.id WHERE cm.request_id = ? ORDER BY cm.created_at ASC`, [req.params.requestId]);
    res.json({ messages });
});

// =============================================================================
// || SOCKET.IO & ERROR HANDLING & SERVER START                               ||
// =============================================================================

io.use((socket, next) => {
    jwt.verify(socket.handshake.auth.token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Authentication error'));
        socket.user = decoded;
        next();
    });
});

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id, 'with user ID:', socket.user.id);
  socket.join(`user_${socket.user.id}`);
  socket.on('join_chat', (requestId) => socket.join(`chat_${requestId}`));
  socket.on('send_message', async ({ requestId, message }) => {
      const senderId = socket.user.id;
      const [reqData] = await pool.execute('SELECT t.driver_id, rr.passenger_id FROM ride_requests rr JOIN trips t ON rr.trip_id = t.id WHERE rr.id = ?', [requestId]);
      if (reqData.length > 0 && (senderId === reqData[0].driver_id || senderId === reqData[0].passenger_id)) {
          const [result] = await pool.execute('INSERT INTO chat_messages (request_id, sender_id, message) VALUES (?, ?, ?)', [requestId, senderId, message]);
          const messageData = { id: result.insertId, request_id: requestId, sender_id: senderId, message, sender_name: socket.user.name };
          io.to(`chat_${requestId}`).emit('new_message', messageData);
      }
  });
  socket.on('disconnect', () => console.log('🔌 User disconnected:', socket.id));
});

app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ message: 'An internal server error occurred' });
});

const PORT = process.env.PORT || 3000;
initDatabase().then(() => {
  server.listen(PORT, () => console.log(`\n🚗 Chalo Server Started on http://localhost:${PORT}`));
});
