const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const users = [
  {
    id: 1,
    name: "Alex Rivera",
    email: "student@campus.edu",
    password: "student123",
    role: "Student",
  },
  {
    id: 2,
    name: "Campus Organizer",
    email: "organizer@campus.edu",
    password: "organizer123",
    role: "Organizer",
  },
];

app.get("/", (req, res) => {
  res.json({
    message: "CampusCount API is running",
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required.",
    });
  }

  const user = users.find(
    (item) => item.email === email && item.password === password,
  );

  if (!user) {
    return res.status(401).json({
      message: "Invalid email or password.",
    });
  }

  res.json({
    message: "Login successful.",
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

app.listen(PORT, () => {
  console.log(`CampusCount API running at http://localhost:${PORT}`);
});