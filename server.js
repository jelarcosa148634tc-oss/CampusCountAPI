
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { Resend } = require("resend");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      message: "Authentication token required.",
    });
  }

  const secret = process.env.JWT_SECRET;

  if (!secret) {
    console.error("JWT_SECRET is not configured.");
    return res.status(500).json({
      message: "Authentication is not configured.",
    });
  }

  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired authentication token.",
    });
  }
}

function requireOrganizer(req, res, next) {
  if (req.user.role !== "Organizer") {
    return res.status(403).json({
      message: "Only organizers can register students.",
    });
  }

  next();
}

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      message: "CampusCount API is running",
      database: "connected",
    });
  } catch (error) {
    console.error("Database connection failed:", error.message);
    res.status(500).json({
      message: "Database connection failed",
    });
  }
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL
        CHECK (role IN ('Student', 'Organizer')),
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
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
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

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role,
              must_change_password
       FROM users
       WHERE LOWER(email) = LOWER($1)`,
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
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      console.error("JWT_SECRET is not configured.");
      return res.status(500).json({
        message: "Authentication is not configured.",
      });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      secret,
      { expiresIn: "8h" }
    );

    return res.json({
      message: "Login successful.",
      token,
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
    return res.status(500).json({
      message: "Unable to log in right now.",
    });
  }
});

app.post(
  "/register-student",
  authenticateToken,
  requireOrganizer,
  async (req, res) => {
    const { firstName, lastName, personalEmail } = req.body;

    if (
      typeof firstName !== "string" ||
      typeof lastName !== "string" ||
      typeof personalEmail !== "string" ||
      !firstName.trim() ||
      !lastName.trim() ||
      !/^[^\s@]+@gmail\.com$/i.test(personalEmail.trim())
    ) {
      return res.status(400).json({
        message:
          "Enter a first name, last name, and valid personal Gmail address.",
      });
    }

    const first = firstName.trim();
    const last = lastName.trim();

    const normalize = (value) =>
      value
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

    const firstInitial = normalize(first).charAt(0);
    const surname = normalize(last);

    if (!firstInitial || !surname) {
      return res.status(400).json({
        message: "Names must contain valid letters or numbers.",
      });
    }

    const campusEmail = `${firstInitial}.${surname}@campus.edu`;
    const name = `${first} ${last}`;
    const recipient = personalEmail.trim().toLowerCase();
    let createdUserId;

    try {
      const existing = await pool.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
        [campusEmail]
      );

      if (existing.rowCount > 0) {
        return res.status(409).json({
          message: "That generated campus email already exists.",
          email: campusEmail,
        });
      }

      const temporaryPassword = crypto.randomBytes(18).toString("base64url");
      const passwordHash = await bcrypt.hash(temporaryPassword, 10);

      const inserted = await pool.query(
        `INSERT INTO users
           (name, email, password_hash, role, personal_email,
            must_change_password)
         VALUES ($1, $2, $3, 'Student', $4, TRUE)
         RETURNING id`,
        [name, campusEmail, passwordHash, recipient]
      );

      createdUserId = inserted.rows[0].id;

      const escapeHtml = (value) =>
        value.replace(/[&<>"']/g, (character) => ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[character]);
if (!resend) {
  throw new Error("RESEND_API_KEY is not configured.");
}
      const emailResult = await resend.emails.send({
        from: "CampusCount <onboarding@resend.dev>",
        to: recipient,
        subject: "Your CampusCount student account",
        html: `
          <h2>Welcome to CampusCount, ${escapeHtml(name)}!</h2>
          <p>Your student account has been created.</p>
          <p><strong>Campus email:</strong> ${escapeHtml(campusEmail)}</p>
          <p><strong>Temporary password:</strong> ${escapeHtml(temporaryPassword)}</p>
          <p>Please change your temporary password after signing in.</p>
        `,
      });

      if (emailResult.error) {
        throw new Error("Resend could not send the registration email.");
      }

      return res.status(201).json({
        message: "Student registered and email sent.",
        student: {
          id: createdUserId,
          name,
          email: campusEmail,
          mustChangePassword: true,
        },
      });
    } catch (error) {
      console.error("Student registration failed:", error.message);

      if (createdUserId) {
        try {
          await pool.query("DELETE FROM users WHERE id = $1", [
            createdUserId,
          ]);
        } catch (cleanupError) {
          console.error(
            "Registration cleanup failed:",
            cleanupError.message
          );
        }
      }

      return res.status(500).json({
        message:
          "Registration failed. Check the API logs and email configuration.",
      });
    }
  }
);

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
