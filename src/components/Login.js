import React, { useState } from 'react';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState(''); // State to store success message

  const users = [
    { username: 'admin', password: 'admin123' },
    { username: 'user', password: 'user123' },
  ];

  const handleLogin = () => {
    // Trim username and password to remove any leading/trailing spaces
    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();

    const user = users.find(
      (user) => user.username === trimmedUsername && user.password === trimmedPassword
    );

    if (user) {
      setSuccessMessage(`Login successful! Welcome, ${trimmedUsername}`); // Set success message
      setError(''); // Clear error message
    } else {
      setError('Invalid username or password');
      setSuccessMessage(''); // Clear any previous success message
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        flexDirection: 'column',
        background: 'linear-gradient(135deg, #74ebd5, #acb6e5)',
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
        <h2 style={{ fontSize: '32px', color: '#007bff', marginBottom: '20px' }}>Login</h2>
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
        <button
          onClick={handleLogin}
          style={{
            padding: '12px 24px',
            backgroundColor: '#007bff',
            color: '#fff',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            marginTop: '20px',
            fontSize: '18px',
            fontWeight: 'bold',
            transition: 'background-color 0.3s',
          }}
          onMouseOver={(e) => (e.target.style.backgroundColor = '#0056b3')}
          onMouseOut={(e) => (e.target.style.backgroundColor = '#007bff')}
        >
          Login
        </button>
        {error && <p style={{ color: 'red', marginTop: '15px', fontSize: '16px' }}>{error}</p>}

        {/* Display login success message */}
        {successMessage && (
          <p style={{ color: 'green', marginTop: '15px', fontSize: '16px' }}>
            {successMessage}
          </p>
        )}
      </div>
    </div>
  );
}

export default Login;
