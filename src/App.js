import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Navbar from './components/Navbar';
import Login from './components/Login';
import Signup from './components/Signup';
import Amendments from './components/Amendments';
import Rules from './components/Rules';
import Educator from './components/Educator'; 
import Citizen from './components/Citizen'; 
import LegalExpert from './components/LegalExpert';


function App() {
  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/amendments" element={<Amendments />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/Educator" element={<Educator />} />
        <Route path="/Citizen" element={<Citizen />} />
      </Routes>
    </Router>
  );
}

export default App;
