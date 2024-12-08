const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/legalExpertDB', { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String,  // Legal Expert, Admin, Educator, Citizen
});

const User = mongoose.model('User', userSchema);

const constitutionContentSchema = new mongoose.Schema({
  title: String,
  content: String,
});

const ConstitutionContent = mongoose.model('ConstitutionContent', constitutionContentSchema);

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization'];
  if (token) {
    jwt.verify(token, 'yourSecretKey', (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Role-based access control middleware
const authorizeLegalExpert = (req, res, next) => {
  if (req.user.role === 'Legal Expert') {
    next();
  } else {
    res.sendStatus(403);
  }
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = new User({ username, password: hashedPassword, role });
  await newUser.save();
  res.send('User registered');
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400).send('Invalid credentials');
  }

  const token = jwt.sign({ username: user.username, role: user.role }, 'yourSecretKey');
  res.json({ token });
});

// Legal Expert: Update constitutional content
app.put('/update-constitution', authenticateJWT, authorizeLegalExpert, async (req, res) => {
  const { title, content } = req.body;
  const updatedContent = await ConstitutionContent.findOneAndUpdate(
    { title },
    { content },
    { new: true }
  );
  if (updatedContent) {
    res.send('Constitution content updated');
  } else {
    res.status(404).send('Content not found');
  }
});

// Get constitutional content
app.get('/get-constitution', async (req, res) => {
  const content = await ConstitutionContent.find();
  res.json(content);
});

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
