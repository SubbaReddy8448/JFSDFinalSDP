import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function Signup() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleSignup = () => {
    if (!username || !password || !confirmPassword) {
      setError('All fields are required.');
      setSuccess('');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      setSuccess('');
      return;
    }

    setError('');
    setSuccess('Signup successful! Redirecting to login...');
    setTimeout(() => navigate('/login'), 2000); // Redirect after 2 seconds
  };

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        flexDirection: 'column',
        background: 'linear-gradient(135deg, #ff9a9e, #fad0c4)',
        fontFamily: "'Arial', sans-serif",
      }}
    >
      <div
        style={{
          padding: '40px',
          border: '2px solid #fff',
          borderRadius: '12px',
          backgroundColor: '#ffffffdd',
          boxShadow: '0px 8px 12px rgba(0, 0, 0, 0.2)',
          textAlign: 'center',
          width: '400px',
        }}
      >
        <h2 style={{ fontSize: '32px', color: '#ff6f61', marginBottom: '20px' }}>Signup</h2>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{
            display: 'block',
            margin: '10px auto',
            padding: '12px',
            width: '90%',
            borderRadius: '6px',
            border: '1px solid #ccc',
            fontSize: '16px',
          }}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            display: 'block',
            margin: '10px auto',
            padding: '12px',
            width: '90%',
            borderRadius: '6px',
            border: '1px solid #ccc',
            fontSize: '16px',
          }}
        />
        <input
          type="password"
          placeholder="Confirm Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          style={{
            display: 'block',
            margin: '10px auto',
            padding: '12px',
            width: '90%',
            borderRadius: '6px',
            border: '1px solid #ccc',
            fontSize: '16px',
          }}
        />
        <button
          onClick={handleSignup}
          style={{
            padding: '12px 24px',
            backgroundColor: '#ff6f61',
            color: '#fff',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            marginTop: '20px',
            fontSize: '18px',
            fontWeight: 'bold',
            transition: 'background-color 0.3s',
          }}
          onMouseOver={(e) => (e.target.style.backgroundColor = '#e55b50')}
          onMouseOut={(e) => (e.target.style.backgroundColor = '#ff6f61')}
        >
          Signup
        </button>
        {error && <p style={{ color: 'red', marginTop: '15px', fontSize: '16px' }}>{error}</p>}
        {success && <p style={{ color: 'green', marginTop: '15px', fontSize: '16px' }}>{success}</p>}
      </div>
    </div>
  );
}

export default Signup;
