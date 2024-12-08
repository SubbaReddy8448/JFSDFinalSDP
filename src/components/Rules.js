import React from 'react';

function Rules() {
  const rulesList = [
    { id: 1, rule: 'Respect the Constitution and its values.' },
    { id: 2, rule: 'Ensure justice and equality for all citizens.' },
    { id: 3, rule: 'Promote harmony and avoid discrimination.' },
    { id: 4, rule: 'Uphold and protect the sovereignty of the nation.' },
    { id: 5, rule: 'Strive for excellence in all spheres of life.' },
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
        overflowY: 'auto',
        padding: '20px',
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
        <h2 style={{ fontSize: '32px', color: '#6a11cb', marginBottom: '20px' }}>Rules</h2>
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {rulesList.map((rule) => (
            <li
              key={rule.id}
              style={{
                marginBottom: '10px',
                padding: '15px',
                backgroundColor: '#f7f7f7',
                borderRadius: '8px',
                boxShadow: '0px 4px 6px rgba(0, 0, 0, 0.1)',
                color: '#333',
              }}
            >
                <p style={{ margin: 0, fontSize: '16px' }}>{rule.rule}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default Rules;
