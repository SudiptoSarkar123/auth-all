const express = require('express');
const app = express();
const path = require('path');
const dotenv = require('dotenv').config();
const dbcon = require('./app/config/dbcon');

// Connect to the database
dbcon();



// Middleware to parse JSON bodies
app.use(express.json());

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Middleware to serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));




// Basic error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});


// my routers
const authRouter = require('./app/router/AuthRouter');
// Use the routers 

app.use('/api',authRouter); 

// Start the server
const PORT = process.env.PORT || 4005;
app.listen(PORT, () => {
    console.log('Server running on port', PORT);
});

