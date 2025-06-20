const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';


// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL Database Connection
const db = mysql.createConnection({
host: process.env.DB_HOST ,
user: process.env.DB_USER,
password: process.env.DB_PASSWORD,
database: process.env.DB_NAME 

});
console.log('Connection config:', db.config);

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
    
    // Create database and tables if they don't exist
    initializeDatabase();
});

// Initialize Database
function initializeDatabase() {
    // Create Users table
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            phone VARCHAR(20),
            is_host BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;

    // Create Listings table
    const createListingsTable = `
        CREATE TABLE IF NOT EXISTS listings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            host_id INT,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            location VARCHAR(255) NOT NULL,
            price DECIMAL(10,2) NOT NULL,
            bedrooms INT NOT NULL,
            bathrooms INT NOT NULL,
            guests INT NOT NULL,
            image VARCHAR(500),
            images JSON,
            amenities JSON,
            rating DECIMAL(3,2) DEFAULT 0.0,
            available BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES users(id)
        )
    `;

    // Create Bookings table
    const createBookingsTable = `
        CREATE TABLE IF NOT EXISTS bookings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            listing_id INT,
            user_id INT,
            check_in DATE NOT NULL,
            check_out DATE NOT NULL,
            guests INT NOT NULL,
            total_price DECIMAL(10,2) NOT NULL,
            status ENUM('pending', 'confirmed', 'cancelled') DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (listing_id) REFERENCES listings(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `;

    // Execute table creation queries
    db.query(createUsersTable, (err) => {
        if (err) {
            console.error('Error creating users table:', err);
        } else {
            console.log('Users table ready');
        }
    });

    db.query(createListingsTable, (err) => {
        if (err) {
            console.error('Error creating listings table:', err);
        } else {
            console.log('Listings table ready');
            // Insert sample data after table creation
            insertSampleData();
        }
    });

    db.query(createBookingsTable, (err) => {
        if (err) {
            console.error('Error creating bookings table:', err);
        } else {
            console.log('Bookings table ready');
        }
    });
}

// Insert sample data
function insertSampleData() {
    // Check if listings already exist
    db.query('SELECT COUNT(*) as count FROM listings', (err, results) => {
        if (err) {
            console.error('Error checking listings:', err);
            return;
        }

        if (results[0].count === 0) {
            const sampleListings = [
                {
                    host_id: 1,
                    title: "Luxury Beachfront Villa",
                    description: "Stunning oceanfront villa with panoramic views of the Pacific Ocean. Perfect for a luxury getaway with family and friends.",
                    location: "Malibu, California",
                    price: 450.00,
                    bedrooms: 4,
                    bathrooms: 3,
                    guests: 8,
                    image: "https://images.unsplash.com/photo-1502780402662-acc01917286e?w=400",
                    images: JSON.stringify([
                        "https://images.unsplash.com/photo-1502780402662-acc01917286e?w=600",
                        "https://images.unsplash.com/photo-1600596542815-ffad4c1539a9?w=300",
                        "https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?w=300",
                        "https://images.unsplash.com/photo-1600566753086-00f18fb6b3ea?w=300"
                    ]),
                    amenities: JSON.stringify(["WiFi", "Pool", "Kitchen", "Parking", "Beach Access", "Air Conditioning"]),
                    rating: 4.9
                },
                {
                    host_id: 1,
                    title: "Cozy Mountain Cabin",
                    description: "Charming log cabin nestled in the Rocky Mountains. Ideal for skiing in winter and hiking in summer.",
                    location: "Aspen, Colorado",
                    price: 280.00,
                    bedrooms: 3,
                    bathrooms: 2,
                    guests: 6,
                    image: "https://images.unsplash.com/photo-1449824913935-59a10b8d2000?w=400",
                    images: JSON.stringify([
                        "https://images.unsplash.com/photo-1449824913935-59a10b8d2000?w=600",
                        "https://images.unsplash.com/photo-1441974231531-c6227db76b6e?w=300",
                        "https://images.unsplash.com/photo-1501594907352-04cda38ebc29?w=300",
                        "https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=300"
                    ]),
                    amenities: JSON.stringify(["WiFi", "Fireplace", "Kitchen", "Parking", "Mountain Views", "Heating"]),
                    rating: 4.7
                },
                {
                    host_id: 1,
                    title: "Modern City Apartment",
                    description: "Sleek and modern apartment in the heart of Manhattan. Walking distance to Times Square and Central Park.",
                    location: "New York, NY",
                    price: 320.00,
                    bedrooms: 2,
                    bathrooms: 2,
                    guests: 4,
                    image: "https://images.unsplash.com/photo-1545324418-cc1a3fa10c00?w=400",
                    images: JSON.stringify([
                        "https://images.unsplash.com/photo-1545324418-cc1a3fa10c00?w=600",
                        "https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?w=300",
                        "https://images.unsplash.com/photo-1560448204-603b3fc33ddc?w=300",
                        "https://images.unsplash.com/photo-1560184897-ae75f418493e?w=300"
                    ]),
                    amenities: JSON.stringify(["WiFi", "Kitchen", "Gym", "Doorman", "City Views", "Air Conditioning"]),
                    rating: 4.8
                },
                {
                    host_id: 1,
                    title: "Charming Countryside Cottage",
                    description: "Authentic Tuscan farmhouse surrounded by vineyards and olive groves. Experience the true Italian countryside.",
                    location: "Tuscany, Italy",
                    price: 200.00,
                    bedrooms: 2,
                    bathrooms: 1,
                    guests: 4,
                    image: "https://images.unsplash.com/photo-1493809842364-78817add7ffb?w=400",
                    images: JSON.stringify([
                        "https://images.unsplash.com/photo-1493809842364-78817add7ffb?w=600",
                        "https://images.unsplash.com/photo-1504597833195-bc532e0abaad?w=300",
                        "https://images.unsplash.com/photo-1605276373954-0c4a0dac5851?w=300",
                        "https://images.unsplash.com/photo-1566073771259-6a8506099945?w=300"
                    ]),
                    amenities: JSON.stringify(["WiFi", "Kitchen", "Garden", "Vineyard Views", "Fireplace", "Parking"]),
                    rating: 4.6
                }
            ];

            // Create a sample host user first
            const sampleHost = {
                name: "John Doe",
                email: "host@stayfinder.com",
                password: bcrypt.hashSync("password123", 10),
                phone: "+1234567890",
                is_host: true
            };

            db.query('INSERT INTO users SET ?', sampleHost, (err, result) => {
                if (err) {
                    console.error('Error creating sample host:', err);
                    return;
                }

                // Insert sample listings
                sampleListings.forEach(listing => {
                    db.query('INSERT INTO listings SET ?', listing, (err) => {
                        if (err) {
                            console.error('Error inserting sample listing:', err);
                        }
                    });
                });

                console.log('Sample data inserted successfully');
            });
        }
    });
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'StayFinder API is running' });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }

        // Check if user already exists
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: 'User already exists with this email' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create user
            const newUser = {
                name,
                email,
                password: hashedPassword,
                phone: phone || null
            };

            db.query('INSERT INTO users SET ?', newUser, (err, result) => {
                if (err) {
                    console.error('Error creating user:', err);
                    return res.status(500).json({ error: 'Failed to create user' });
                }

                // Generate JWT token
                const token = jwt.sign(
                    { id: result.insertId, email, name },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.status(201).json({
                    message: 'User registered successfully',
                    user: {
                        id: result.insertId,
                        name,
                        email
                    },
                    token
                });
            });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = results[0];

            // Check password
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    is_host: user.is_host
                },
                token
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Listings Routes
app.get('/api/listings', (req, res) => {
    const { location, guests, minPrice, maxPrice } = req.query;
    
    let query = 'SELECT * FROM listings WHERE available = true';
    let queryParams = [];

    // Add filters
    if (location) {
        query += ' AND location LIKE ?';
        queryParams.push(`%${location}%`);
    }

    if (guests) {
        query += ' AND guests >= ?';
        queryParams.push(parseInt(guests));
    }

    if (minPrice) {
        query += ' AND price >= ?';
        queryParams.push(parseFloat(minPrice));
    }

    if (maxPrice) {
        query += ' AND price <= ?';
        queryParams.push(parseFloat(maxPrice));
    }

    query += ' ORDER BY created_at DESC';

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching listings:', err);
            return res.status(500).json({ error: 'Failed to fetch listings' });
        }

        // Parse JSON fields
        const listings = results.map(listing => ({
            ...listing,
           images: (() => {
    if (Array.isArray(listing.images)) return listing.images;

    if (typeof listing.images === 'string') {
        try {
            const parsed = JSON.parse(listing.images);
            if (Array.isArray(parsed)) return parsed;
        } catch {
            // Not JSON, try splitting manually
            return listing.images.split(',').map(url => url.trim());
        }
    }

    return []; // fallback if undefined or unexpected type
})(),


           amenities: (() => {
    const raw = listing.amenities;
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
        try {
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : raw.split(',').map(a => a.trim());
        } catch {
            return raw.split(',').map(a => a.trim());
        }
    }
    if (typeof raw === 'object' && raw !== null && raw.toString) {
        const str = raw.toString();
        return str.includes(',') ? str.split(',').map(a => a.trim()) : [str];
    }
    return [];
})()

        }));

        res.json({ listings });
    });
});

app.get('/api/listings/:id', (req, res) => {
    const listingId = req.params.id;

    db.query('SELECT * FROM listings WHERE id = ?', [listingId], (err, results) => {
        if (err) {
            console.error('Error fetching listing:', err);
            return res.status(500).json({ error: 'Failed to fetch listing' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Listing not found' });
        }

       const listing = {
    ...results[0],
    images: (() => {
        const raw = results[0].images;
        if (Array.isArray(raw)) return raw;
        if (typeof raw === 'string') {
            try {
                const parsed = JSON.parse(raw);
                return Array.isArray(parsed) ? parsed : raw.split(',').map(url => url.trim());
            } catch {
                return raw.split(',').map(url => url.trim());
            }
        }
        if (typeof raw === 'object' && raw !== null && raw.toString) {
            const str = raw.toString();
            return str.includes(',') ? str.split(',').map(url => url.trim()) : [str];
        }
        return [];
    })(),
    amenities: (() => {
        const raw = results[0].amenities;
        if (Array.isArray(raw)) return raw;
        if (typeof raw === 'string') {
            try {
                const parsed = JSON.parse(raw);
                return Array.isArray(parsed) ? parsed : raw.split(',').map(item => item.trim());
            } catch {
                return raw.split(',').map(item => item.trim());
            }
        }
        if (typeof raw === 'object' && raw !== null && raw.toString) {
            const str = raw.toString();
            return str.includes(',') ? str.split(',').map(item => item.trim()) : [str];
        }
        return [];
    })()
};

res.json({ listing });

});
});

// Create new listing (protected route)
app.post('/api/listings', authenticateToken, (req, res) => {
    const {
        title,
        description,
        location,
        price,
        bedrooms,
        bathrooms,
        guests,
        image,
        images,
        amenities
    } = req.body;

    // Validation
    if (!title || !location || !price || !bedrooms || !bathrooms || !guests) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const newListing = {
        host_id: req.user.id,
        title,
        description: description || '',
        location,
        price: parseFloat(price),
        bedrooms: parseInt(bedrooms),
        bathrooms: parseInt(bathrooms),
        guests: parseInt(guests),
        image: image || '',
        images: JSON.stringify(images || []),
        amenities: JSON.stringify(amenities || [])
    };

    db.query('INSERT INTO listings SET ?', newListing, (err, result) => {
        if (err) {
            console.error('Error creating listing:', err);
            return res.status(500).json({ error: 'Failed to create listing' });
        }

        res.status(201).json({
            message: 'Listing created successfully',
            listing: { id: result.insertId, ...newListing }
        });
    });
});

// Get host's listings (protected route)
app.get('/api/host/listings', authenticateToken, (req, res) => {
    db.query('SELECT * FROM listings WHERE host_id = ?', [req.user.id], (err, results) => {
        if (err) {
            console.error('Error fetching host listings:', err);
            return res.status(500).json({ error: 'Failed to fetch listings' });
        }

        const listings = results.map(listing => ({
            ...listing,
            images: JSON.parse(listing.images || '[]'),
            amenities: JSON.parse(listing.amenities || '[]')
        }));

        res.json({ listings });
    });
});

// Bookings Routes
app.post('/api/bookings', authenticateToken, (req, res) => {
    const { listingId, checkIn, checkOut, guests, totalPrice } = req.body;

    // Validation
    if (!listingId || !checkIn || !checkOut || !guests) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if listing exists and is available
    db.query('SELECT * FROM listings WHERE id = ? AND available = true', [listingId], (err, results) => {
        if (err) {
            console.error('Error checking listing:', err);
            return res.status(500).json({ error: 'Failed to check listing availability' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Listing not found or not available' });
        }

        // Check for conflicting bookings
        const conflictQuery = `
            SELECT * FROM bookings 
            WHERE listing_id = ? 
            AND status != 'cancelled'
            AND (
                (check_in <= ? AND check_out > ?) OR
                (check_in < ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
            )
        `;

        db.query(conflictQuery, [listingId, checkIn, checkIn, checkOut, checkOut, checkIn, checkOut], (err, conflicts) => {
            if (err) {
                console.error('Error checking booking conflicts:', err);
                return res.status(500).json({ error: 'Failed to check booking availability' });
            }

            if (conflicts.length > 0) {
                return res.status(400).json({ error: 'Selected dates are not available' });
            }

            // Calculate price if not provided
            let calculatedPrice = totalPrice;
            if (!calculatedPrice) {
                const listing = results[0];
                const start = new Date(checkIn);
                const end = new Date(checkOut);
                const nights = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
                calculatedPrice = nights * listing.price;
            }

            // Create booking
            const newBooking = {
                listing_id: listingId,
                user_id: req.user.id,
                check_in: checkIn,
                check_out: checkOut,
                guests: parseInt(guests),
                total_price: parseFloat(calculatedPrice),
                status: 'confirmed'
            };

            db.query('INSERT INTO bookings SET ?', newBooking, (err, result) => {
                if (err) {
                    console.error('Error creating booking:', err);
                    return res.status(500).json({ error: 'Failed to create booking' });
                }

                res.status(201).json({
                    message: 'Booking created successfully',
                    booking: { id: result.insertId, ...newBooking }
                });
            });
        });
    });
});

// Get user's bookings (protected route)
app.get('/api/bookings', authenticateToken, (req, res) => {
    const query = `
        SELECT b.*, l.title as listing_title, l.location as listing_location, l.image as listing_image
        FROM bookings b
        JOIN listings l ON b.listing_id = l.id
        WHERE b.user_id = ?
        ORDER BY b.created_at DESC
    `;

    db.query(query, [req.user.id], (err, results) => {
        if (err) {
            console.error('Error fetching bookings:', err);
            return res.status(500).json({ error: 'Failed to fetch bookings' });
        }

        res.json({ bookings: results });
    });
});

// Get host's bookings (protected route)
app.get('/api/host/bookings', authenticateToken, (req, res) => {
    const query = `
        SELECT b.*, l.title as listing_title, u.name as guest_name, u.email as guest_email
        FROM bookings b
        JOIN listings l ON b.listing_id = l.id
        JOIN users u ON b.user_id = u.id
        WHERE l.host_id = ?
        ORDER BY b.created_at DESC
    `;

    db.query(query, [req.user.id], (err, results) => {
        if (err) {
            console.error('Error fetching host bookings:', err);
            return res.status(500).json({ error: 'Failed to fetch bookings' });
        }

        res.json({ bookings: results });
    });
});



// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

app.use(express.static(__dirname));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});


// Start server
app.listen(PORT, () => {
    console.log(`StayFinder API server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    db.end();
    process.exit(0);
});