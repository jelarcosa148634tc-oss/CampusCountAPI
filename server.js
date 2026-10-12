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
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

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
    CREATE TABLE IF NOT EXISTS events (
      id VARCHAR(100) PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      date VARCHAR(50) NOT NULL,
      time VARCHAR(50) NOT NULL,
      place VARCHAR(255) NOT NULL,
      kind VARCHAR(100) NOT NULL,
      color VARCHAR(20) NOT NULL,
      attending INTEGER NOT NULL DEFAULT 0,
      latitude DOUBLE PRECISION NOT NULL DEFAULT 0,
      longitude DOUBLE PRECISION NOT NULL DEFAULT 0,
      radius DOUBLE PRECISION NOT NULL DEFAULT 100,
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS program VARCHAR(150)
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
      [user.email],
    );

    if (existing.rowCount === 0) {
      const passwordHash = await bcrypt.hash(user.password, 10);

      await pool.query(
        `INSERT INTO users (name, email, password_hash, role)
         VALUES ($1, $2, $3, $4)`,
        [user.name, user.email, passwordHash, user.role],
      );
    }
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS event_registrations (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      event_id VARCHAR(100) NOT NULL,
      event_title VARCHAR(255) NOT NULL,
      event_date VARCHAR(50),
      event_time VARCHAR(50),
      event_place VARCHAR(255),
      registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (student_id, event_id)
    )
  `);

  console.log(
    "PostgreSQL connected; users and event registrations tables are ready.",
  );
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
              must_change_password, program
       FROM users
       WHERE LOWER(email) = LOWER($1)`,
      [email.trim()],
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

    const token = jwt.sign({ id: user.id, role: user.role }, secret, {
      expiresIn: "8h",
    });

    return res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        program: user.program,
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
    const { firstName, lastName, password, program } = req.body;

    const allowedPrograms = [
      "Information Technology",
      "Computer Science",
      "Information Systems",
      "Computer Engineering",
      "Electronics Engineering",
      "Electronics Engineering",
      "Data Science",
      "Cybersecurity",
      "Information Technology Education",
      "Other technology-related program",
    ];

    if (
      typeof firstName !== "string" ||
      typeof lastName !== "string" ||
      typeof password !== "string" ||
      typeof program !== "string" ||
      !firstName.trim() ||
      !lastName.trim() ||
      password.length < 8 ||
      !allowedPrograms.includes(program)
    ) {
      return res.status(400).json({
        message:
          "Enter valid names, a password of at least 8 characters, and a valid program.",
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
    const name = `${first} ${last}`;

    if (!firstInitial || !surname) {
      return res.status(400).json({
        message: "Names must contain valid letters or numbers.",
      });
    }

    try {
      // Reserve the next ID from the users table sequence.
      const idResult = await pool.query(
        "SELECT nextval(pg_get_serial_sequence('users', 'id')) AS id",
      );

      const studentId = Number(idResult.rows[0].id);

      // Example: j.delacruz.3@campus.edu
      const campusEmail = `${firstInitial}.${surname}.${studentId}@campus.edu`;

      const passwordHash = await bcrypt.hash(password, 10);

      const inserted = await pool.query(
        `INSERT INTO users
          (id, name, email, password_hash, role, personal_email,
           must_change_password, program)
         VALUES ($1, $2, $3, $4, 'Student', NULL, FALSE, $5)
         RETURNING id`,
        [studentId, name, campusEmail, passwordHash, program],
      );

      return res.status(201).json({
        message: "Student account created successfully.",
        student: {
          id: inserted.rows[0].id,
          name,
          email: campusEmail,
          program,
          mustChangePassword: false,
        },
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          message: "That student ID or campus email already exists.",
        });
      }

      console.error("Student registration failed:", error.message);

      return res.status(500).json({
        message: "Unable to create the student account.",
      });
    }
  },
);

app.get("/events", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.id, e.title, e.date, e.time, e.place, e.kind, e.color,
        COUNT(r.id)::INTEGER AS attending,
        e.latitude, e.longitude, e.radius
 FROM events e
 LEFT JOIN event_registrations r ON r.event_id = e.id
 GROUP BY e.id
 ORDER BY e.created_at DESC`
    );

    return res.json({ events: result.rows });
  } catch (error) {
    console.error("Fetching events failed:", error.message);
    return res.status(500).json({
      message: "Unable to load events.",
    });
  }
});

app.post("/events", authenticateToken, async (req, res) => {
  if (req.user.role !== "Organizer") {
    return res.status(403).json({
      message: "Only organizers can create events.",
    });
  }

  const {
    id,
    title,
    date,
    time,
    place,
    kind,
    color,
    latitude,
    longitude,
    radius,
  } = req.body;

  if (
    typeof id !== "string" ||
    !id.trim() ||
    typeof title !== "string" ||
    !title.trim() ||
    typeof date !== "string" ||
    !date.trim() ||
    typeof time !== "string" ||
    !time.trim() ||
    typeof place !== "string" ||
    !place.trim() ||
    typeof kind !== "string" ||
    !kind.trim() ||
    typeof color !== "string" ||
    !color.trim() ||
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude) ||
    !Number.isFinite(radius) ||
    radius <= 0
  ) {
    return res.status(400).json({
      message: "Please provide valid event details.",
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO events
        (id, title, date, time, place, kind, color,
         latitude, longitude, radius, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, title, date, time, place, kind, color,
                 attending, latitude, longitude, radius`,
      [
        id.trim(),
        title.trim(),
        date.trim(),
        time.trim(),
        place.trim(),
        kind.trim(),
        color.trim(),
        latitude,
        longitude,
        radius,
        req.user.id,
      ],
    );

    return res.status(201).json({
      message: "Event created successfully.",
      event: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "This event ID already exists.",
      });
    }

    console.error("Creating event failed:", error.message);
    return res.status(500).json({
      message: "Unable to create event.",
    });
  }
});

app.post("/event-registrations", authenticateToken, async (req, res) => {
  if (req.user.role !== "Student") {
    return res.status(403).json({
      message: "Only students can register for events.",
    });
  }

  const { eventId, eventTitle, eventDate, eventTime, eventPlace } = req.body;

  if (
    typeof eventId !== "string" ||
    !eventId.trim() ||
    typeof eventTitle !== "string" ||
    !eventTitle.trim()
  ) {
    return res.status(400).json({
      message: "Event ID and title are required.",
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO event_registrations
        (student_id, event_id, event_title, event_date, event_time, event_place)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (student_id, event_id) DO NOTHING
       RETURNING id, event_id, event_title, event_date, event_time,
                 event_place, registered_at`,
      [
        req.user.id,
        eventId.trim(),
        eventTitle.trim(),
        typeof eventDate === "string" ? eventDate : null,
        typeof eventTime === "string" ? eventTime : null,
        typeof eventPlace === "string" ? eventPlace : null,
      ],
    );

    if (result.rowCount === 0) {
      return res.status(409).json({
        message: "You are already registered for this event.",
      });
    }

    return res.status(201).json({
      message: "Event registration saved.",
      registration: result.rows[0],
    });
  } catch (error) {
    console.error("Event registration failed:", error.message);
    return res.status(500).json({
      message: "Unable to save event registration.",
    });
  }
});

app.get("/event-registrations", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, event_id, event_title, event_date, event_time,
              event_place, registered_at
       FROM event_registrations
       WHERE student_id = $1
       ORDER BY registered_at DESC`,
      [req.user.id],
    );

    return res.json({ registrations: result.rows });
  } catch (error) {
    console.error("Fetching event registrations failed:", error.message);
    return res.status(500).json({
      message: "Unable to load event registrations.",
    });
  }
});

app.delete(
  "/event-registrations/:eventId",
  authenticateToken,
  async (req, res) => {
    if (req.user.role !== "Student") {
      return res.status(403).json({
        message: "Only students can cancel event registrations.",
      });
    }

    try {
      const result = await pool.query(
        `DELETE FROM event_registrations
         WHERE student_id = $1 AND event_id = $2
         RETURNING id`,
        [req.user.id, req.params.eventId],
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          message: "Registration not found.",
        });
      }

      return res.json({ message: "Event registration cancelled." });
    } catch (error) {
      console.error("Cancelling event registration failed:", error.message);
      return res.status(500).json({
        message: "Unable to cancel event registration.",
      });
    }
  },
);
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`CampusCount API running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
