import React from 'react';
import { Link } from 'react-router-dom';

function Navbar() {
  return (
    <nav style={{ background: '#333', padding: '10px' }}>
      <ul style={{ listStyleType: 'none', display: 'flex', justifyContent: 'space-around' }}>
        <li><Link to="/login" style={{ color: '#fff', textDecoration: 'none' }}>Login</Link></li>
        <li><Link to="/signup" style={{ color: '#fff', textDecoration: 'none' }}>Signup</Link></li>
        <li><Link to="/amendments" style={{ color: '#fff', textDecoration: 'none' }}>Amendments</Link></li>
        <li><Link to="/rules" style={{ color: '#fff', textDecoration: 'none' }}>Rules</Link></li>
        <li><Link to="/Educator" style={{ color: '#fff', textDecoration: 'none' }}>Educator</Link></li>
        <li><Link to="/Citizen" style={{ color: '#fff', textDecoration: 'none' }}>Citizen</Link></li>
        <li><Link to="/LegalExpert" style={{ color: '#fff', textDecoration: 'none' }}>LegalExpert</Link></li>
      </ul>
    </nav>
  );
}

export default Navbar;
