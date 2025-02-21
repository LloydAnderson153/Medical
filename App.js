import React, { useState } from 'react';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import './App.css';


function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('patient');  // Default role is 'patient'
  const [token, setToken] = useState('');
  const [patients, setPatients] = useState([]);
  const [selectedPatient, setSelectedPatient] = useState(null);
  const [ssn, setSsn] = useState('');
  const [userRole, setUserRole] = useState('');
  const [patientName, setPatientName] = useState('');
  const [patientAge, setPatientAge] = useState('');
  const [patientMedicalHistory, setPatientMedicalHistory] = useState('');
  const [patientSSN, setPatientSSN] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const special = /[\/;<>,-]+/;
  const [records, setRecords] = useState([]);
  const curUser = 'guest';
  const [unlockUsername, setUnlockUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');

/*const fetchAccessRecords = async () => {
  try {
    logAction("Access records", "viewing");
    const response = await axios.get('http://localhost:3001/doctor/access-records', {
      headers: { Authorization: `Bearer ${token}` }
    });
    setRecords(response.data);
  } catch (error) {
    alert('Failed to fetch access records');
  }
};*/

const fetchAccessRecords = async () => {
  try {
    const response = await axios.get('http://localhost:3001/admin/access-records', {
      headers: { Authorization: `Bearer ${token}` }
    });
    setRecords(response.data); // Populate the records in the state
  } catch (error) {
    console.error('Fetch error:', error);
    alert('Failed to fetch access records');
  }
};




  /*const fetchPatientBySSN = async () => {
    if (!ssn) {
      alert('Please enter a valid SSN.');
      logAction("Access patient", "failed ssn entry");
      return;
    }
    try {
      logAction("Access patient", "viewing");
      const response = await axios.get(`http://localhost:3001/patients/${ssn}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    const fetchedPatient = Array.isArray(response.data);//? response.data[0] : response.data;
    setSelectedPatient(fetchedPatient);
    } catch (error) {
      console.error("Fetch error:", error);
      alert('Error fetching patient');
      setSelectedPatient(null);
    }
  };*/
  const fetchPatientBySSN = async () => {
    if (!ssn) {
      alert('Please enter a valid SSN.');
      return;
    }
  
    try {
      logAction("Access patient", "viewing");
      const response = await axios.get(`http://localhost:3001/patients/${ssn}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSelectedPatient(response.data); // Expecting a single patient object
    } catch (error) {
      console.error('Fetch error:', error);
      alert('Error fetching patient');
      setSelectedPatient(null);
    }
  };

  const handleInputChange = (setter) => (e) => {
    const { value } = e.target;
    const special = /[\/;<>,-]+/; 
  
    if (special.test(value)) { 
      alert("Special characters /, ;, -, and , are not allowed.");
    } else {
      setter(value);
    }
  };

  const handleSignup = async () => {
    try {
      if (username.length === 0 || password.length === 0) {
        logAction("Access users", "account creation failed");
        alert('You can not input that.');
        return;
      }
      logAction("Access users", "create account");
      await axios.post('http://localhost:3001/signup', { username, password, role });
      alert('Signup successful');
    } catch (error) {
      alert('Signup failed');
      console.error("Signup error:", error);
    }
  };

  const handleLogin = async () => {
    if (username.length === 0 || password.length === 0) {
      //curUser = username;
      logAction("Access users", "account login failed");
      
      alert('You can not input that.');
      return;
    }
    try {
      //curUser = username;
      logAction("Access users", "logging in");
      const response = await axios.post('http://localhost:3001/login', { username, password });
      setToken(response.data.token);
      const decodedToken = JSON.parse(atob(response.data.token.split('.')[1]));
      setUserRole(decodedToken.role);
      setIsLoggedIn(true);
      alert('Login successful');
    } catch (error) {
      alert('Login failed');
    }
  };

  const handleAddPatient = async () => {
    try {
      if (!patientSSN) {
        alert("SSN is required");
        return;
      }
     logAction("Access patients", "adding patient");
      const patientData = {
        name: patientName,
        age: parseInt(patientAge),  // Convert age to integer
        medical_history: patientMedicalHistory,
        ssn: patientSSN,
      };
      await axios.post('http://localhost:3001/patients', patientData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert('Patient added successfully');
    } catch (error) {
      alert('Failed to add patient');
      console.error("Add patient error:", error);
    }
  };

  const fetchPatients = async () => {
    try {
     logAction("Access patients", "viewing patient");
      const response = await axios.get('http://localhost:3001/patients', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPatients(response.data);
    } catch (error) {
      alert('Failed to fetch patients');
    }
  };


  const handleLogout = () => {
  logAction("Access log out", "account log out");
    setToken('');
    setUserRole('');
    setIsLoggedIn(false);
    setUsername('');
    setPassword('');
    alert('Logged out successfully');
    //curUser = 'guest';
  };

  function logAction(what_was_accessed, why) {
    const currentdate = new Date();
    const datetime = (currentdate.getMonth() + 1) + "/" +
                     currentdate.getDate() + "/" +
                     currentdate.getFullYear() + " @ " +
                     currentdate.getHours() + ":" +
                     currentdate.getMinutes() + ":" +
                     currentdate.getSeconds();
  
    // Log data payload
    const logData = {
      who_accessed: username,
      what_was_accessed,
      when_accessed: datetime,
      why,
    };
  
    // Send a POST request to the server's logging endpoint
    axios.post('http://localhost:3001/records', logData)
      .then(response => {
        console.log('Log action recorded successfully:', response.data);
      })
      .catch(error => {
        console.error('Error recording log action:', error.message);
      });
  }

  /*
          <h2>Patient Records</h2>
          <button onClick={fetchPatients}>Load Patients</button>
          {patients.length > 0 && (
            <table border="1">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Age</th>
                  <th>Medical History</th>
                </tr>
              </thead>
              <tbody>
                {patients.map((patient, index) => (
                  <tr key={index}>
                    <td>{patient.name}</td>
                    <td>{patient.age}</td>
                    <td>{patient.medical_history}</td>
                  </tr>
                ))}
              </tbody>
           </table>
          )}
          </div> */

  const handleUnlockAccount = async () => {
    try {
      const response = await axios.post('http://localhost:3001/admin/unlock-account', {
        username: unlockUsername,
        newPassword: newPassword,
        
      }, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      alert(response.data.message);
    } catch (error) {
      console.error("Unlock account error:", error);
      alert('Failed to unlock account');
    }
  };


  return (
    <div>
      <h1>Medical Management System Demo</h1>
      {!token ? (
        <div>
          <h2>Login</h2>
          <input type="text" placeholder="Username" onChange={handleInputChange(setUsername)} />
          <input type="password" placeholder="Password" onChange={handleInputChange(setPassword)} />
          <button onClick={handleLogin}>Login</button>
          
          <h2>Signup</h2>
          <input type="text" placeholder="Username" onChange={handleInputChange(setUsername)} />
          <input type="password" placeholder="Password" onChange={handleInputChange(setPassword)} />
          <select onChange={e => setRole(e.target.value)} value={role}>
            <option value="patient">Patient</option>
            <option value="doctor">Doctor</option>
            <option value="admin">Admin</option>
          </select>
          <button onClick={handleSignup}>Signup</button>
        </div>
      ) : (
        <div>
          <h2>Welcome, {userRole}</h2>
          <button onClick={handleLogout}>Logout</button>
          {userRole === 'doctor' && (
        <div> 
      
          </div>
        )}
        {userRole === 'admin' && (
        <div>
          <h2>Access Records</h2>
          <button onClick={fetchAccessRecords}>Fetch Access Records</button>
          {records.length > 0 && (
            <table border="1">
              <thead>
                <tr>
                  <th>who</th>
                  <th>what</th>
                  <th>when</th>
                  <th>why</th>
                </tr>
              </thead>
              <tbody>
                {records.map((records, index) => (
                  <tr key={index}>
                    <td>{records.who_accessed}</td>
                    <td>{records.what_was_accessed}</td>
                    <td>{records.when_accessed}</td>
                    <td>{records.why}</td>
                  </tr>
                ))}
              </tbody>
           </table>
          )}
          </div>
        )}
          {userRole === 'doctor' && (
            <div>
              <h3>Add New Patient</h3>
              <form onSubmit={(e) => { e.preventDefault(); handleAddPatient(); }}>
                <input
                  type="text"
                  placeholder="Patient Name"
                  value={patientName}
                  onChange={(e) => setPatientName(e.target.value)}
                />
                <input
                  type="number"
                  placeholder="Patient Age"
                  value={patientAge}
                  onChange={(e) => setPatientAge(e.target.value)}
                />
                <input
                  type="text"
                  placeholder="Medical History"
                  value={patientMedicalHistory}
                  onChange={(e) => setPatientMedicalHistory(e.target.value)}
                />
                <input
                  type="text"
                  placeholder="SSN"
                  value={patientSSN}
                  onChange={(e) => setPatientSSN(e.target.value)}
                />
                <button type="submit">Add Patient</button>
              </form>
          </div>
        )}
        {userRole === 'admin' && (
          <div>
            <h2>Unlock Account</h2>
            <input 
             type="text" 
             placeholder="Username" 
             value={unlockUsername} 
             onChange={(e) => setUnlockUsername(e.target.value)} 
             
            />
            <button onClick={handleUnlockAccount}>Unlock Account</button>
          </div>
      )}


          {userRole === 'doctor' && (
            <div>
              <h2>Search Patient by SSN</h2>
              <input type="text" placeholder="Enter SSN" onChange={handleInputChange(setSsn)} value={ssn} />
              <button onClick={fetchPatientBySSN}>Search</button>
              {selectedPatient && (
                <div className="patient-info-menu">
                <h2>Patient Details</h2>
                <p><strong>Name:</strong> {selectedPatient.name}</p>
                <p><strong>Age:</strong> {selectedPatient.age}</p>
                <p><strong>SSN:</strong> {selectedPatient.ssn}</p>
                <p><strong>medical_history:</strong> {selectedPatient.medical_history}</p>
              </div>
              )}
              <ul>
              {Array.isArray(patients) && patients.map(patient => (
              <div key={patient.id}>
              </div>
                ))}
              </ul>
            </div>
          )}
        
      
        </div>
      )}
    </div>
  );
}

export default App;