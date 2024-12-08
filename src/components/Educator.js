// src/modules/Educator.js
import React, { useState } from 'react';

function Educator() {
  const [content, setContent] = useState('');
  const [contentList, setContentList] = useState([]);

  const handleCreateContent = () => {
    if (content) {
      setContentList([...contentList, content]);
      setContent('');
    } else {
      alert('Please enter content.');
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.heading}>Educator Module - Create Content</h2>
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Enter educational content..."
        style={styles.textarea}
      />
      <button onClick={handleCreateContent} style={styles.button}>
        Create Content
      </button>

      <h3 style={styles.subheading}>Existing Content</h3>
      <ul style={styles.contentList}>
        {contentList.map((contentItem, index) => (
          <li key={index} style={styles.contentItem}>
            {contentItem}
          </li>
        ))}
      </ul>
    </div>
  );
}

const styles = {
  container: {
    padding: '20px',
    textAlign: 'center',
    background: 'linear-gradient(135deg, #74ebd5, #acb6e5)',
    borderRadius: '10px',
    boxShadow: '0 4px 8px rgba(0, 0, 0, 0.2)',
    maxWidth: '600px',
    margin: '20px auto',
  },
  heading: {
    fontSize: '32px',
    color: '#007bff',
  },
  subheading: {
    fontSize: '24px',
    color: '#333',
  },
  textarea: {
    width: '80%',
    height: '150px',
    padding: '10px',
    borderRadius: '6px',
    border: '1px solid #ccc',
    fontSize: '16px',
    marginBottom: '20px',
  },
  button: {
    padding: '12px 24px',
    backgroundColor: '#007bff',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '18px',
    fontWeight: 'bold',
  },
  contentList: {
    listStyleType: 'none',
    padding: '0',
  },
  contentItem: {
    background: '#f4f4f4',
    margin: '10px 0',
    padding: '10px',
    borderRadius: '6px',
    border: '1px solid #ccc',
  },
};

export default Educator;
