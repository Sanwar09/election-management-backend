// Import required modules
const bcrypt = require('bcryptjs');
const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
require('dotenv').config();  // For loading environment variables

// Initialize Express app
const app = express();

// MySQL Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'pass123',
  database: process.env.DB_NAME || 'election_db'
});

// Connect to MySQL Database
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL Database');
});

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 3600000 // 1 hour session
  }
}));

// Middleware to check if the user is logged in
const checkAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Please log in first' });
  }
  next();  // Continue to the next middleware or route handler
};

// User Registration API (POST /register)
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate the input (optional)
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required' });
  }

  // Check if the email already exists in the database
  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailQuery, [email], async (err, results) => {
    if (err) {
      console.error('Error checking email:', err);
      return res.status(500).json({ message: 'Error checking email' });
    }

    // If the email exists, send an error response
    if (results.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    try {
      // Hash the password before saving it in the database
      const hashedPassword = await bcrypt.hash(password, 10);

      // SQL query to insert the new user into the database
      const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
      db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) {
          console.error('Error registering user:', err);
          return res.status(500).json({ message: 'Error registering user', error: err });
        }
        res.status(201).json({ message: 'User registered successfully' });
      });

    } catch (error) {
      console.error('Error hashing password:', error);
      res.status(500).json({ message: 'Error hashing password', error: error });
    }
  });
});

// User Login API (POST /login)
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Validate the input (optional)
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Error checking email:', err);
      return res.status(500).json({ message: 'Error checking email' });
    }

    // If user doesn't exist, return an error
    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare the password with the hashed password in the database
    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Set session data after successful login
    req.session.userId = user.id;
    res.status(200).json({ message: 'Login successful' });
  });
});

// Get list of candidates API (GET /candidates)
app.get('/candidates', (req, res) => {
  const query = 'SELECT * FROM candidates';  // Replace with your candidates table name
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching candidates:', err);
      return res.status(500).json({ message: 'Error fetching candidates' });
    }
    res.status(200).json(results);  // Return the list of candidates
  });
});

// Vote API (POST /vote)
app.post('/vote', checkAuth, (req, res) => {
  const { candidateId } = req.body;

  if (!candidateId) {
    return res.status(400).json({ message: 'Candidate ID is required' });
  }

  // Check if the user has already voted
  const checkVoteQuery = 'SELECT * FROM votes WHERE user_id = ?';
  db.query(checkVoteQuery, [req.session.userId], (err, results) => {
    if (err) {
      console.error('Error checking vote:', err);
      return res.status(500).json({ message: 'Error checking vote' });
    }

    if (results.length > 0) {
      return res.status(400).json({ message: 'You have already voted' });
    }

    // Insert the vote into the votes table
    const voteQuery = 'INSERT INTO votes (user_id, candidate_id) VALUES (?, ?)';
    db.query(voteQuery, [req.session.userId, candidateId], (err, result) => {
      if (err) {
        console.error('Error voting:', err);
        return res.status(500).json({ message: 'Error voting' });
      }
      res.status(200).json({ message: 'Vote registered successfully' });
    });
  });
});

// Get election results API (GET /results)
app.get('/results', (req, res) => {
  const query = `
    SELECT candidates.name, COUNT(votes.candidate_id) AS vote_count
    FROM candidates
    LEFT JOIN votes ON candidates.id = votes.candidate_id
    GROUP BY candidates.id
    ORDER BY vote_count DESC;
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching election results:', err);
      return res.status(500).json({ message: 'Error fetching results' });
    }
    res.status(200).json(results);  // Return the election results
  });
});

// Logout API (POST /logout) - To destroy session
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Error logging out' });
    }
    res.status(200).json({ message: 'Logged out successfully' });
  });
});

// Start the server
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});
