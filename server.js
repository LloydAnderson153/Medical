const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const app = express();

const cors = require('cors');
app.use(cors());


app.use(express.json());  // Middleware to parse JSON bodies

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');  // In-memory DB for demo

// Create tables (users and patient records)
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, locked BOOLEAN DEFAULT FALSE, failedattempts INTEGER DEFAULT 0)");
  db.run("CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, medical_history TEXT, ssn TEXT UNIQUE)");
  db.run("CREATE TABLE records (id INTEGER PRIMARY KEY, who_accessed TEXT, what_was_accessed TEXT, when_accessed TEXT, why Text)");
});

/*const exampleUsers = [
  { username: 'user1', password: 1234, role: 'patient', locked: true },
  { username: 'user2', password: 1234, role: 'admin', locked: false },
  { username: 'user3', password: 1234, role: 'doctor', locked: false }
];

exampleUsers.forEach(user => {
  db.run("INSERT INTO users (username, password, role, locked) VALUES (?, ?, ?, ?)", [user.username, user.password, user.role, user.locked]);
});

*/
const examplePatients = [
  { name: 'John Doe', age: 22, medical_history: 'Fish odor syndrome', ssn: '123456789' },
  { name: 'Jane Smith', age: 22, medical_history: 'Sleeping Beauty syndrome, COVID19', ssn: '987654321' },
  { name: 'Lloyd Anderson', age: 22, medical_history: 'No conditions', ssn: '11111111' }
];

examplePatients.forEach(patient => {
  const encryptedSSN = bcrypt.hashSync(patient.ssn, 10); // Hash the SSN for security
  db.run("INSERT INTO patients (name, age, medical_history, ssn) VALUES (?, ?, ?, ?)", [patient.name, patient.age, patient.medical_history, encryptedSSN]);
});

/*const exampleRecords = [
  {who_accessed: 'John', what_was_accessed: 'gdfs', when_accessed: '11/20/2024', why: 'fdvnbdf' },
  {who_accessed: 'Bob', what_was_accessed: 'dfgdfsgdsfa', when_accessed: '11/14/2024', why: 'dsfhdsaf' }
];

exampleRecords.forEach(records => {
  db.run("INSERT INTO records (who_accessed, what_was_accessed, when_accessed, why) VALUES (?, ?, ?, ?)", [records.who_accessed, records.what_was_accessed, records.when_accessed, records.why]);
});

*/

const defaultAdminUsername = 'admin';
const defaultAdminPassword = '1234';
const defaultAdminRole = 'admin';
const hashedAdminPassword = bcrypt.hashSync(defaultAdminPassword, 10);

const defaultDoctorUsername = 'doctor';
const defaultDoctorPassword = '1234';
const defaultDoctorRole = 'doctor';
const hashedDoctorPassword = bcrypt.hashSync(defaultDoctorPassword, 10);

const defaultPatientUsername = 'patient';
const defaultPatientPassword = '1234';
const defaultNewPatientPassword = '12345';
const defaultPatientRole = 'patient';
const hashedPatientPassword = bcrypt.hashSync(defaultPatientPassword, 10);
const hashedNewPatientPassword = bcrypt.hashSync(defaultNewPatientPassword, 10);

// Simple signup endpoint (hash password)
app.post('/signup', (req, res) => {
  const { username, password, role } = req.body;

  const validRoles = ['doctor', 'admin', 'patient'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role' });
  }
  const hashedPassword = bcrypt.hashSync(password, 10); 

  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role], function (err) {
    if (err) return res.status(500).json({ message: 'Error registering user' });
    res.status(200).json({ message: 'User created' });
  });
});

/*
const checkRole = (roles) => {
  return (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    jwt.verify(token, 'secretkey', (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });

      // Check if the user has a valid role
      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Access denied: insufficient permissions' });
      }
      req.user = decoded;
      next();
    });
  };
};*/
const checkRole = (roles) => {
  return (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    jwt.verify(token, 'secretkey', (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });

      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Access denied: insufficient permissions' });
      }
      req.user = decoded; // Attach decoded data to request
      next();
    });
  };
};

// Admin can create new users (admin, doctor, patient roles)
app.post('/admin/create-user', checkRole(['admin']), (req, res) => {
  const { username, password, role } = req.body;

  const validRoles = ['doctor', 'admin', 'patient'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);  // Hash password

  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role], function (err) {
    if (err) return res.status(500).json({ message: 'Error registering user' });
    res.status(200).json({ message: 'User created' });
  });
});

// Admin can unlock accounts (reset password for users)
app.post('/admin/unlock-account', checkRole(['admin']), (req, res) => {
  const { username, newPassword } = req.body;
  failedattempts = 0;
  const hashedPassword = bcrypt.hashSync(newPassword, 10);  // Hash new password
  failedattempts = 0;
  db.run("UPDATE users SET password = ? WHERE username = ?", [hashedPassword, username], function (err) {
    if (err) return res.status(500).json({ message: 'Error unlocking account' });
    failedattempts = 0;
    res.status(200).json({ message: 'Account unlocked successfully' });
    failedattempts = 0;
  });
});

// Admin can view patient records
app.get('/admin/records', checkRole(['admin']), (req, res) => {
  db.all("SELECT * FROM patients", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching records' });
    res.status(200).json(rows);
  });
});


/*
app.get('/admin/access-records', checkRole(['admin']), (req, res) => {
  db.all("SELECT * FROM records", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching access records' });
    res.status(200).json(rows);
  });
});
*/

app.get('/admin/access-records', checkRole(['admin']), (req, res) => {
  console.log('Decoded Token:', req.user); // Log the decoded token
  db.all("SELECT * FROM records", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching access records', error: err.message });
    res.status(200).json(rows);
  });
});


/*const CryptoJS = require('crypto-js');
const SECRET_KEY = 'your_secret_key';  // Use a secure key

app.post('/patients', authenticate, (req, res) => {
  const { name, age, medical_history, ssn } = req.body;

  // Encrypt SSN
  const encryptedSSN = CryptoJS.AES.encrypt(ssn, SECRET_KEY).toString();

  db.run("INSERT INTO patients (name, age, medical_history, ssn) VALUES (?, ?, ?, ?)",
    [name, age, medical_history, encryptedSSN],
    function (err) {
      if (err) return res.status(500).json({ message: 'Error adding patient' });
      res.status(200).json({ message: 'Patient added' });
    });
});
app.get('/patients/:ssn', authenticate, (req, res) => {
  const { ssn } = req.params;

  db.get("SELECT * FROM patients WHERE ssn = ?", [ssn], (err, row) => {
    if (err) return res.status(500).json({ message: 'Error fetching patient' });
    if (!row) return res.status(404).json({ message: 'Patient not found' });

    // Decrypt SSN
    const decryptedSSN = CryptoJS.AES.decrypt(row.ssn, SECRET_KEY).toString(CryptoJS.enc.Utf8);
    row.ssn = decryptedSSN;

    res.status(200).json(row);
  });
});
*/

// Simple login endpoint (check password)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'User not found' });

    if (row.locked) {
      return res.status(400).json({ message: 'Account is locked. Please contact an admin.' });
    }

    if (bcrypt.compareSync(password, row.password)) {
      db.run("UPDATE users SET failedattempts = 0 WHERE id = ?", [row.id]);
      const token = jwt.sign({ userId: row.id, role: row.role }, 'secretkey', { expiresIn: '1h' });
      res.status(200).json({ token });
    } else {
      db.run("UPDATE users SET failedattempts = failedattempts + 1 WHERE id = ?", [row.id]);
      if (row.failedattempts >= 3) {
        db.run("UPDATE users SET locked = TRUE WHERE id = ?", [row.id]);
      }
      res.status(400).json({ message: 'Incorrect password' });
    }
  });
});

// Middleware to verify JWT (for protected routes)
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Access denied' });

  jwt.verify(token, 'secretkey', (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Endpoint to fetch patient records (protected)
app.post('/patients', authenticate, (req, res) => {
  const { name, age, medical_history } = req.body;
  db.run("INSERT INTO patients (name, age, medical_history) VALUES (?, ?, ?)", [name, age, medical_history], function (err) {
    if (err) return res.status(500).json({ message: 'Error adding patient' });
    res.status(200).json({ message: 'Patient added' });
  });
});

app.get('/patients/:ssn', authenticate, (req, res) => {
  const { ssn } = req.params;

  // Fetch all patients and compare SSNs using bcrypt
  db.all("SELECT * FROM patients", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching patients', error: err.message });

    // Find the patient with the matching SSN
    const patient = rows.find((row) => bcrypt.compareSync(ssn, row.ssn));
    if (!patient) return res.status(404).json({ message: 'Patient not found' });

    res.status(200).json(patient); // Return the matched patient
  });
});


/*app.get('/patients/:ssn', authenticate, (req, res) => {
  const {ssn} = req.params;
  db.get("SELECT * FROM patients WHERE ssn = ?", [ssn], (err, row) => {
    if (err) return res.status(500).json({ message: 'Error fetching patient' });
    if (row && bcrypt.compareSync(ssn, row.ssn)) {
      res.status(200).json(row);
    } else {
      res.status(404).json({ message: 'Patient not found' });
    }
  });
});
*/

app.get('/doctor/patients', checkRole(['doctor']), (req, res) => {
  db.all("SELECT name, age, medical_history FROM patients", [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching patients' });
    res.status(200).json(rows);
  });
});

// Add patient record (for demo purposes)
app.post('/patients', authenticate, checkRole(['doctor']), (req, res) => {
  const {name, age, medical_history, ssn} = req.body;
  const encryptedSSN = bcrypt.hashSync(ssn, 10);
  db.run("INSERT INTO patients (name, age, medical_history, ssn) VALUES (?, ?, ?, ?)", [name, age, medical_history, encryptedSSN], function (err) {
    if (err) return res.status(500).json({ message: 'Error adding patient'});
    res.status(200).json({ message: 'Patient added' });
  });
});

app.post('/records', (req, res) => {
  const { who_accessed, what_was_accessed, when_accessed, why } = req.body;

  // Validate required fields
  if (!who_accessed || !what_was_accessed || !when_accessed || !why) {
    return res.status(400).json({ message: 'Missing required log fields' });
  }

  // Insert log entry into the database
  db.run(
    "INSERT INTO records (who_accessed, what_was_accessed, when_accessed, why) VALUES (?, ?, ?, ?)",
    [who_accessed, what_was_accessed, when_accessed, why],
    function (err) {
      if (err) {
        console.error("Error saving log:", err);
        return res.status(500).json({ message: 'Error saving log' });
      }
      res.status(200).json({ message: 'Log saved successfully' });
    }
  );
});


// Start server
const port = 3001;
// Define a simple route for the home page
app.get('/', (req, res) => {
  res.send('Welcome to the Medical Management System API');
});
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
