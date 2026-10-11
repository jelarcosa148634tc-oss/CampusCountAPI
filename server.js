
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ message: "CampusCount API is running", database: "connected" });
  } catch (error) {
    console.error("Database connection failed:", error.message);
    res.status(500).json({ message: "Database connection failed" });
  }
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('Student', 'Organizer')),
      personal_email VARCHAR(255),
      must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const demoUsers = [
    {
      name: "Alex Rivera",
      email: "student@campus.edu",
      password: "student123",
      role: "Student",
    },
    {
      name: "Campus Organizer",
      email: "organizer@campus.edu",
      password: "organizer123",
      role: "Organizer",
    },
  ];

  for (const user of demoUsers) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [user.email]
    );

    if (existing.rowCount === 0) {
      const passwordHash = await bcrypt.hash(user.password, 10);

      await pool.query(
        `INSERT INTO users (name, email, password_hash, role)
         VALUES ($1, $2, $3, $4)`,
        [user.name, user.email, passwordHash, user.role]
      );
    }
  }

  console.log("PostgreSQL connected; users table is ready.");
}

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role,
              must_change_password
       FROM users WHERE LOWER(email) = LOWER($1)`,
      [email.trim()]
    );

    if (
      result.rowCount === 0 ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const user = result.rows[0];

    res.json({
      message: "Login successful.",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        mustChangePassword: user.must_change_password,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Unable to log in right now." });
  }
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`CampusCount API running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  });
