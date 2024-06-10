const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const JWT_SECRET = "secret";

const app = express();

app.use(express.json()); // Parses JSON-formatted request bodies

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  next();
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401); // if no token, return unauthorized

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // if token is not valid, return forbidden

    // Verify user ID from token with the database
    const query = `SELECT userid FROM accounts WHERE userid = ?`;
    db.get(query, [user.userid], (err, row) => {
      if (err) return res.sendStatus(500); // if database error, return server error
      if (!row) return res.sendStatus(403); // if user not found, return forbidden

      req.user = user;
      next();
    });
  });
};

// Register User
app.post("/register", async (req, res) => {
  const { username, password, balance } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query = `INSERT INTO accounts (username, password, balance) VALUES (?, ?, ?)`;
  const params = [username, hashedPassword, balance];

  db.run(query, params, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const token = jwt.sign({ userid: this.lastID }, JWT_SECRET, {
      expiresIn: "24h",
    });
    res.status(201).json({ token, userid: this.lastID });
  });
});

// Login User
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM accounts WHERE username = ?`;
  const params = [username];

  db.get(query, params, async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ userid: user.userid }, JWT_SECRET, {
        expiresIn: "24h",
      });
      res.json({ token, userid: user.userid });
    } else {
      res.status(400).json({ error: "Invalid credentials" });
    }
  });
});

// Balance checking
app.get("/balance", authenticateToken, (req, res) => {
  const userid = req.user.userid;

  const query = `SELECT balance FROM accounts WHERE userid = ?`;
  const params = [userid];

  db.get(query, params, (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: "Account not found" });
    }
    res.json({ balance: row.balance });
  });
});

// Deposit
app.post("/deposit", authenticateToken, (req, res) => {
  const userid = req.user.userid;
  const amount = req.body.amount;

  if (amount <= 0) {
    return res.status(400).json({ error: "Deposit amount must be positive" });
  }

  const updateQuery = `UPDATE accounts SET balance = balance + ? WHERE userid = ?`;
  const selectQuery = `SELECT balance FROM accounts WHERE userid = ?`;

  db.run(updateQuery, [amount, userid], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    db.get(selectQuery, [userid], (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: "Deposit successful", balance: row.balance });
    });
  });
});


// Withdrawal
app.post("/withdraw", authenticateToken, (req, res) => {
  const userid = req.user.userid;
  const amount = req.body.amount;

  if (amount <= 0) {
    return res.status(400).json({ error: "Withdrawal amount must be positive" });
  }

  const selectQuery = `SELECT balance FROM accounts WHERE userid = ?`;
  const updateQuery = `UPDATE accounts SET balance = balance - ? WHERE userid = ?`;

  db.get(selectQuery, [userid], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: "Account not found" });
    }
    if (row.balance < amount) {
      return res.status(400).json({ error: "Insufficient funds" });
    }

    db.run(updateQuery, [amount, userid], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      db.get(selectQuery, [userid], (err, row) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({
          message: "Withdrawal successful",
          balance: row.balance,
        });
      });
    });
  });
});