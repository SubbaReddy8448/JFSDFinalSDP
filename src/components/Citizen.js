import React, { useState } from 'react';

function Citizen() {
  const [progress, setProgress] = useState(0);
  const [quizScore, setQuizScore] = useState(null);
  const [isQuizActive, setIsQuizActive] = useState(false);
  const [selectedOption, setSelectedOption] = useState(null);

  const questions = [
    {
      question: "What is the supreme law of India?",
      options: ["Constitution", "Parliament", "Prime Minister", "President"],
      correctAnswer: "Constitution",
    },
    {
      question: "Who is known as the Father of the Nation?",
      options: ["Jawaharlal Nehru", "Mahatma Gandhi", "Subhas Chandra Bose", "Dr. B.R. Ambedkar"],
      correctAnswer: "Mahatma Gandhi",
    },
    {
      question: "Which article of the Indian Constitution deals with the Fundamental Rights?",
      options: ["Article 12", "Article 21", "Article 32", "Article 19"],
      correctAnswer: "Article 21",
    },
    {
      question: "Who was the first President of India?",
      options: ["Dr. Rajendra Prasad", "Dr. Sarvepalli Radhakrishnan", "Jawaharlal Nehru", "Indira Gandhi"],
      correctAnswer: "Dr. Rajendra Prasad",
    },
    {
      question: "Which is the longest river in India?",
      options: ["Ganga", "Yamuna", "Godavari", "Indus"],
      correctAnswer: "Ganga",
    },
  ];

  const handleQuizCompletion = () => {
    let score = 0;
    questions.forEach((q) => {
      if (q.correctAnswer === selectedOption) {
        score += 20; // Assuming 20 points per correct answer
      }
    });
    setQuizScore(score);
    setIsQuizActive(false);
    setProgress(progress + 20); // Example of progress increment
  };

  const handleOptionChange = (event) => {
    setSelectedOption(event.target.value);
  };

  const startQuiz = () => {
    setIsQuizActive(true);
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.heading}>Citizen Module - Learn and Participate</h2>
      <div style={styles.section}>
        <h3 style={styles.subheading}>Available Content</h3>
        <p style={styles.contentDescription}>
          Learn about the Indian Constitution, its history, Fundamental Rights, and more. Start by viewing the lessons and taking quizzes to enhance your knowledge.
        </p>
      </div>

      <div style={styles.section}>
        <h3 style={styles.subheading}>Progress Tracker</h3>
        <p style={styles.progress}>Your Progress: {progress}%</p>
        {quizScore !== null && (
          <p style={styles.quizResult}>Quiz Score: {quizScore} / 100</p>
        )}
      </div>

      {isQuizActive ? (
        <div style={styles.section}>
          <h3 style={styles.subheading}>Quiz</h3>
          {questions.map((q, index) => (
            <div key={index} style={styles.questionContainer}>
              <p style={styles.question}>{q.question}</p>
              {q.options.map((option, idx) => (
                <div key={idx} style={styles.option}>
                  <input
                    type="radio"
                    id={option}
                    name={`question-${index}`}
                    value={option}
                    onChange={handleOptionChange}
                  />
                  <label htmlFor={option}>{option}</label>
                </div>
              ))}
            </div>
          ))}
          <button onClick={handleQuizCompletion} style={styles.button}>
            Submit Quiz
          </button>
        </div>
      ) : (
        <div style={styles.section}>
          <h3 style={styles.subheading}>Take a Quiz</h3>
          <button onClick={startQuiz} style={styles.button}>
            Start Quiz
          </button>
        </div>
      )}
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
  section: {
    marginBottom: '20px',
  },
  contentDescription: {
    fontSize: '18px',
    color: '#333',
  },
  progress: {
    fontSize: '20px',
    color: '#28a745',
  },
  quizResult: {
    fontSize: '18px',
    color: '#007bff',
  },
  button: {
    padding: '12px 24px',
    backgroundColor: '#007bff',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    margin: '10px',
    fontSize: '18px',
    fontWeight: 'bold',
  },
  questionContainer: {
    marginBottom: '15px',
    textAlign: 'left',
  },
  question: {
    fontSize: '18px',
    fontWeight: 'bold',
  },
  option: {
    margin: '10px 0',
  },
};

export default Citizen;
