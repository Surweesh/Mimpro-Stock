const express = require('express');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

// Initialize Express app
const app = express();
const port = 170;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));  // Ensure 'public' is the correct folder for static files

// Initialize SQLite database (Ensure stockuser.db is in the same directory)
const db = new sqlite3.Database('stockuser.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
    }
});

// Create the stockuser table if it does not exist
db.run(`
    CREATE TABLE IF NOT EXISTS stockuser (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
`);

// Route to serve registration page
app.get('/registration', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'registration.html'));  // Adjust path to where your registration.html is located
});

// Route to serve login page (sign-in)
app.get('/signin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signin.html'));  // Adjust path to where your signin.html is located
});

// Route for user registration (sign up)
app.post('/registration', async (req, res) => {
    const { email, username, password } = req.body;

    // Validate input fields
    if (!email || !username || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const query = 'INSERT INTO stockuser (email, username, password) VALUES (?, ?, ?)';
        db.run(query, [email, username, hashedPassword], function (err) {
            if (err) {
                console.error('Error inserting user:', err.message);
                return res.status(500).json({ error: 'Database error: ' + err.message });
            }

            // Send success response
            res.status(201).json({
                message: 'User registered successfully',
                userId: this.lastID
            });
        });
    } catch (error) {
        console.error('Error during registration:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route for user sign-in (log in)
app.post('/signin', (req, res) => {
    const { email, password } = req.body;

    // Fetch the user by email
    const query = 'SELECT * FROM stockuser WHERE email = ?';
    db.get(query, [email], async (err, user) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            return res.status(500).json({ error: 'Database error: ' + err.message });
        }

        // Check if user exists
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Verify the password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Successful login
        res.status(200).json({ message: 'Logged in successfully!' });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
