const express = require("express"); // Express framework for building the API
const jwt = require("jsonwebtoken"); // JWT library for token generation and verification
const rateLimit = require("express-rate-limit"); // Middleware for rate limiting to prevent brute-force attacks
const { z } = require("zod"); // Zod library for input validation to ensure data integrity
require("dotenv").config(); // Load environment variables from .env file for configuration

const app = express(); // Create an instance of the Express application
const PORT = process.env.PORT || 3000; // Define the port the server will listen on, defaulting to 3000 if not specified
const JWT_SECRET = process.env.JWT_SECRET; // Secret key for signing JWTs, loaded from environment variables for security

app.use(express.json()); // Middleware to parse incoming JSON requests, allowing us to access req.body

// ---------------- USERS (Demo Only) ---------------- In a real application, this data would come from a database and passwords would be hashed
const users = [
  {
    id: 1,
    username: "wayne",
    password: "Password123!",
    role: "user",
  },
  {
    id: 2,
    username: "admin",
    password: "Admin123!",
    role: "admin",
  },
];

// ---------------- RATE LIMIT ---------------- Limit login attempts to prevent brute-force attacks
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: {
    error: "Too many login attempts. Please try again later.",
  },
});

// ---------------- INPUT VALIDATION ---------------- Define a schema for validating login input using Zod to ensure that the username and password meet basic requirements
const loginSchema = z.object({
  username: z.string().min(3),
  password: z.string().min(8),
});

// ---------------- AUTH MIDDLEWARE ---------------- Middleware to authenticate JWT tokens for protected routes, ensuring that only authenticated users can access certain endpoints
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("[SECURITY] Missing token attempt");
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("[SECURITY] Invalid token attempt");
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

// ---------------- ADMIN CHECK ---------------- Middleware to check if the authenticated user has admin privileges, ensuring that only users with the admin role can access certain endpoints
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    console.log(
      `[SECURITY] Unauthorized admin access attempt by user: ${req.user.username}`
    );

    return res.status(403).json({
      error: "Admin access required",
    });
  }

  next();
}

// ---------------- ROUTES ---------------- Define the API routes, including a home route, a login route with rate limiting and input validation, a protected profile route that requires authentication, and an admin route that requires both authentication and admin privileges

// Home
app.get("/", (req, res) => {
  res.json({
    message: "API Security Assessment & Hardening Project",
    status: "running",
  });
});

// Login (with rate limit + validation) This route handles user login, validating the input against the defined schema, checking credentials against the demo user data, and generating a JWT token for successful logins. It also logs security-related events for monitoring purposes.
app.post("/login", loginLimiter, (req, res) => {
  const validation = loginSchema.safeParse(req.body);

  if (!validation.success) {
    console.log("[SECURITY] Invalid login input format");

    return res.status(400).json({
      error: "Invalid input",
      details: validation.error.errors,
    });
  }

  const { username, password } = validation.data;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    console.log(`[SECURITY] Failed login attempt for username: ${username}`);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "15m" }
  );

  console.log(`[SECURITY] Successful login for username: ${username}`);

  res.json({
    message: "Login successful",
    token,
  });
});

// Protected profile route This route is protected by the authenticateToken middleware, ensuring that only authenticated users can access it. It returns a message along with the user's information extracted from the JWT token, demonstrating how to access protected resources based on authentication.
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Secure profile data",
    user: req.user,
  });
});

// Admin route This route is protected by both the authenticateToken and requireAdmin middleware, ensuring that only authenticated users with admin privileges can access it. It returns a message along with sensitive data that should only be visible to admins, demonstrating how to implement role-based access control in the API.
app.get("/admin", authenticateToken, requireAdmin, (req, res) => {
  res.json({
    message: "Admin dashboard accessed",
    sensitiveData: "Only admins should see this.",
  });
});

// ---------------- START SERVER ---------------- Start the Express server and listen on the defined port, logging a message to indicate that the API is running and accessible at the specified URL.
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});