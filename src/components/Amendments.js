import React from 'react';

function Amendments() {
  const amendmentsList = [
    { id: 1, title: 'First Amendment', description: 'Empowered the state to make special provisions for the advancement of socially and educationally backward classes.' },
    { id: 2, title: 'Second Amendment', description: 'Known as the "Mini-Constitution," it added the words "Socialist," "Secular," and "Integrity" to the Preamble..' },
    { id: 3, title: 'Third Amendment', description: 'Established Panchayati Raj institutions in rural areas' },
  ];

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        flexDirection: 'column',
        background: 'linear-gradient(135deg, #6a11cb, #2575fc)',
        fontFamily: "'Arial', sans-serif",
        color: '#fff',
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
          width: '600px',
        }}
      >
        <h2 style={{ fontSize: '32px', color: '#6a11cb', marginBottom: '20px' }}>Amendments</h2>
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {amendmentsList.map((amendment) => (
            <li
              key={amendment.id}
              style={{
                marginBottom: '20px',
                padding: '15px',
                backgroundColor: '#f7f7f7',
                borderRadius: '8px',
                boxShadow: '0px 4px 6px rgba(0, 0, 0, 0.1)',
                color: '#333',
              }}
            >
              <h3 style={{ margin: '0 0 10px 0', color: '#2575fc' }}>{amendment.title}</h3>
              <p style={{ margin: 0 }}>{amendment.description}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default Amendments;
