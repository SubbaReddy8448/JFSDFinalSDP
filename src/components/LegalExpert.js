import React, { useState, useEffect } from 'react';
import axios from 'axios';

const LegalExpert = () => {
  const [contentTitle, setContentTitle] = useState('');
  const [contentBody, setContentBody] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [constitutionContent, setConstitutionContent] = useState([]);

  // Fetch existing constitutional content on load
  useEffect(() => {
    const fetchConstitutionContent = async () => {
      try {
        const response = await axios.get('http://localhost:5000/get-constitution', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setConstitutionContent(response.data);
      } catch (error) {
        console.error('Error fetching content', error);
        alert('Failed to fetch content');
      }
    };

    if (token) {
      fetchConstitutionContent();
    }
  }, [token]);

  const handleUpdateConstitution = async () => {
    if (!contentTitle || !contentBody) {
      alert('Please fill all fields');
      return;
    }

    try {
      const response = await axios.put(
        'http://localhost:5000/update-constitution',
        { title: contentTitle, content: contentBody },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      alert(response.data);
    } catch (error) {
      console.error('Error updating content', error);
      alert('Failed to update content');
    }
  };

  return (
    <div>
      <h1>Legal Expert: Update Constitutional Content</h1>

      <div>
        <h2>Existing Constitutional Content</h2>
        <ul>
          {constitutionContent.length > 0 ? (
            constitutionContent.map((content) => (
              <li key={content._id}>
                <strong>{content.title}</strong>: {content.content}
              </li>
            ))
          ) : (
            <li>No content available</li>
          )}
        </ul>
      </div>

      <input
        type="text"
        placeholder="Content Title"
        value={contentTitle}
        onChange={(e) => setContentTitle(e.target.value)}
      />
      <textarea
        placeholder="Content Body"
        value={contentBody}
        onChange={(e) => setContentBody(e.target.value)}
      ></textarea>
      <button onClick={handleUpdateConstitution}>Update Content</button>
    </div>
  );
};

export default LegalExpert;
