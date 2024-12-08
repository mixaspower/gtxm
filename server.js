const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const port = 3000;
const HOST = '0.0.0.0';
const { Keypair } = require('@solana/web3.js');
const bs58 = require('bs58'); // Import bs58 for encoding
const { Connection, clusterApiUrl, PublicKey } = require('@solana/web3.js');
const { getAccount, TOKEN_PROGRAM_ID } = require('@solana/spl-token');
const path = require('path'); 
const axios = require('axios');


// Set up the view engine to EJS
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set up session for login state management
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: 'postgresql://thedb_ep2i_user:ytbdAh5oAdGD9vLzg0uJhurDk6xuTVRZ@dpg-ctad1qggph6c73enncg0-a.oregon-postgres.render.com/thedb_ep2i',
  ssl: {
    rejectUnauthorized: false
  }
});


// Ορισμός view engine
app.set('views', path.join(__dirname, 'views'));

// Καθορίστε το φάκελο που περιέχει το mypage.html
app.use(express.static(path.join(__dirname, 'public')));

// Όταν κάποιος επισκέπτεται το root domain, ανακατευθύνεται στο mypage.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});


// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/login');
}

// Helper function to generate a 6-digit unique task ID
async function generateUniqueTaskId() {
  let taskId;
  let isUnique = false;

  while (!isUnique) {
    // Generate a random 6-digit number as a string
    taskId = Math.floor(100000 + Math.random() * 900000).toString();

    // Check if the task ID already exists in the database
    const result = await pool.query('SELECT task_id FROM tasks WHERE task_id = $1', [taskId]);
    if (result.rows.length === 0) {
      isUnique = true;
    }
  }

  return taskId;
}


app.use(express.json()); // This should be before your route handlers

// Route for registration
app.get('/register', (req, res) => {
  res.render('auth/register');
});





// app.post('/register', async (req, res) => {
//   const { email, password, refCodeInvitedBy } = req.body;

//   // Validate required fields
//   if (!email || !password) {
//     return res.status(400).json({ error: 'Email and password are required.' });
//   }

//   // Generate a unique referral code for the user
//   const generateRefCode = () => Math.random().toString(36).substr(2, 8);
//   const refCodeInvite = generateRefCode();

//   try {
//     // Hash the password for security
//     const hashedPassword = await bcrypt.hash(password, 10);

//     let validRefCode = null;

//     if (refCodeInvitedBy) {
//       // Verify the referral code exists in the database
//       const referrerQuery = await pool.query(
//         'SELECT "refCodeInvite" FROM users WHERE "refCodeInvite" = $1',
//         [refCodeInvitedBy]
//       );

//       if (referrerQuery.rows.length > 0) {
//         validRefCode = referrerQuery.rows[0].refCodeInvite;
//       } else {
//         return res.status(400).json({ error: 'Invalid referral code.' });
//       }
//     }

//     // Insert the new user into the database
//     await pool.query(
//       `INSERT INTO users 
//       (email, password, earn_level_id, today_remaining_tasks, balance, "refCodeInvite", "refCodeInvitedBy") 
//       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
//       [email, hashedPassword, 0, 3, 0, refCodeInvite, validRefCode]
//     );

//     // Return success with a redirect URL
//     res.status(200).json({ success: true, redirectUrl: '/dashboard' });
//   } catch (err) {
//     if (err.code === '23505') {
//       // Handle unique constraint violations (e.g., duplicate email)
//       res.status(400).json({ error: 'Email already exists. Try another email.' });
//     } else {
//       res.status(500).json({ error: 'Error during registration. Please try again.' });
//       console.error(err);
//     }
//   }
// });


app.post('/register', async (req, res) => {
  const { email, password, refCodeInvitedBy } = req.body;

  // Έλεγχος για τα υποχρεωτικά πεδία
  if (!email || !password) {
    return res.status(400).json({ error: 'Το email και ο κωδικός πρόσβασης είναι υποχρεωτικά.' });
  }

  // Δημιουργία ενός μοναδικού userID βασισμένο στον τρέχοντα χρόνο (μόνο με αριθμούς)
  function generateUserID() {
    const timestamp = Date.now().toString(); // Get current timestamp as a string
    const userID = timestamp.slice(-6); // Take the last 6 digits
    return userID;
  }

  const userID = generateUserID();

  // Δημιουργία ενός μοναδικού κωδικού παραπομπής για τον χρήστη (6 χαρακτήρες, μόνο κεφαλαία και αριθμοί)
  function generateRefCode() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let refCode = '';
    for (let i = 0; i < 6; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      refCode += characters[randomIndex];
    }
    return refCode;
  }

  const refCodeInvite = generateRefCode();

  try {
    // Κρυπτογράφηση του κωδικού πρόσβασης για ασφάλεια
    const hashedPassword = await bcrypt.hash(password, 10);

    let validRefCode = null;

    if (refCodeInvitedBy) {
      // Έλεγχος αν ο κωδικός παραπομπής υπάρχει στη βάση δεδομένων
      const referrerQuery = await pool.query(
        'SELECT "refCodeInvite" FROM users WHERE "refCodeInvite" = $1',
        [refCodeInvitedBy]
      );

      if (referrerQuery.rows.length > 0) {
        validRefCode = referrerQuery.rows[0].refCodeInvite;
      } else {
        return res.status(400).json({ error: 'Ο κωδικός πρόσκλησης δεν είναι έγκυρος.' });
      }
    }

    // Εισαγωγή του νέου χρήστη στη βάση δεδομένων
    const result = await pool.query(
      `INSERT INTO users 
      (user_id, email, password, earn_level_id, today_remaining_tasks, balance, "refCodeInvite", "refCodeInvitedBy") 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *`, // Επιστρέφει τον εισαχθέντα χρήστη
      [userID, email, hashedPassword, 0, 3, 0, refCodeInvite, validRefCode]
    );

    const newUser = result.rows[0];

    // Αποθήκευση του χρήστη στο session
    req.session.user = newUser;

    // Επιστροφή επιτυχίας με URL ανακατεύθυνσης
    res.status(200).json({ success: true, redirectUrl: '/dashboard' });
  } catch (err) {
    if (err.code === '23505') {
      // Αντιμετώπιση παραβιάσεων μοναδικότητας (π.χ., email που υπάρχει ήδη)
      res.status(400).json({ error: 'Το email χρησιμοποιείται ήδη.' });
    } else {
      res.status(500).json({ error: 'Σφάλμα κατά την εγγραφή. Δοκιμάστε ξανά αργότερα.' });
      console.error(err);
    }
  }
});






// Route for login
app.get('/login', (req, res) => {
  res.render('auth/login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.user = user;
        return res.json({ success: true, redirect: '/dashboard' });
      } else {
        return res.status(401).json({ success: false, message: 'Μη έγκυρο email ή κωδικός.' });
      }
    } else {
      return res.status(401).json({ success: false, message: 'Μη έγκυρο email ή κωδικός.' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Σφάλμα κατά τη σύνδεση. Παρακαλώ δοκιμάστε ξανά.' });
  }
});


// Route for logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error during logout. Please try again.');
    }
    res.redirect('/login');
  });
});

// Dashboard route
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

app.get('/home', isAuthenticated, async (req,res) => {
  res.render('home', { user: req.session.user });
});


function isValidSolanaAddress(address) {
  try {
    const publicKey = new PublicKey(address);
    return PublicKey.isOnCurve(publicKey.toBuffer());
  } catch {
    return false;
  }
}


function isValidSolanaAddress(address) {
  try {
    const publicKey = new PublicKey(address);
    return PublicKey.isOnCurve(publicKey.toBuffer());
  } catch {
    return false;
  }
}

function isValidAmount(amount) {
  return amount && !isNaN(amount) && amount > 0;
}

app.post('/withdraw', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.user_id;
    const { amount, walletAddress } = req.body; // Destructure walletAddress and amount from the request body

    // Log the received amount and wallet address for debugging
    console.log('Received amount:', amount);
    console.log('Received wallet address:', walletAddress);

    // Validate the wallet address using @solana/web3.js
    if (!isValidSolanaAddress(walletAddress)) {
      return res.status(400).json({ message: 'Η διεύθυνση που έβαλες δεν είναι σωστή.' });
    }

    // Validate the amount
    if (!isValidAmount(amount)) {
      return res.status(400).json({ message: 'Το ποσό πρέπει να είναι θετικός αριθμός.' });
    }

    // Query to get the current balance of the user
    const userResult = await pool.query('SELECT balance FROM users WHERE user_id = $1', [userId]);

    if (userResult.rows.length > 0) {
      const currentBalance = parseFloat(userResult.rows[0].balance);

      // Check if the requested withdrawal amount is less than or equal to the current balance
      if (amount <= currentBalance) {
        const newBalance = currentBalance - amount;

        // Start a transaction
        await pool.query('BEGIN');

        try {
          // Update the balance in the database
          await pool.query('UPDATE users SET balance = $1 WHERE user_id = $2', [newBalance, userId]);

          // Insert a record into the withdrawal_requests table
          await pool.query(
            `INSERT INTO withdrawal_requests (user_id, amount, to_wallet, created_at)
             VALUES ($1, $2, $3, now())`,
            [userId, amount, walletAddress]
          );

          // Commit the transaction
          await pool.query('COMMIT');

          // Update the session with the new balance
          req.session.user.balance = newBalance;

          // Respond with the updated balance
          res.status(200).json({ newBalance });
        } catch (transactionError) {
          // Rollback the transaction in case of an error
          await pool.query('ROLLBACK');
          console.error('Error during transaction:', transactionError);
          res.status(500).json({ message: 'Error processing the withdrawal. Please try again.' });
        }
      } else {
        res.status(400).json({ message: 'Δεν έχεις αρκετό υπόλοιπο.' });
      }
    } else {
      res.status(404).json({ message: 'Ο χρήστης δεν βρέθηκε.' });
    }
  } catch (err) {
    console.error('Error handling withdrawal:', err); // Log the actual error
    res.status(500).json({ message: 'Error processing the withdrawal. Please try again.' });
  }
});






app.get('/page/vip', isAuthenticated, async (req, res) => {
  try {
    const userId = req.user ? req.user.id : req.session.user ? req.session.user.user_id : null;

    if (!userId) {
      return res.status(400).send('User information is missing');
    }

    // Replace 'id' with the correct column name, e.g., 'user_id'
    const result = await pool.query('SELECT earn_level_id FROM users WHERE user_id = $1', [userId]);

    if (result.rows.length > 0) {
      res.render('vip', {
        vipLevelId: result.rows[0].earn_level_id
      });
    } else {
      res.status(404).send('User not found');
    }
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Internal server error');
  }
});






// Route to serve the 'earn' page with categorized tasks
app.get('/page/earn', isAuthenticated, async (req, res) => {
  try {
    console.log("kalese to earn");
    const userId = req.session.user.user_id;

    // Get user's remaining tasks and VIP level
    const userResult = await pool.query('SELECT earn_level_id, today_remaining_tasks FROM users WHERE user_id = $1', [userId]);
    if (userResult.rows.length > 0) {
      const { earn_level_id, today_remaining_tasks } = userResult.rows[0];

      // Fetch the pay amount per task based on VIP level
      const vipResult = await pool.query('SELECT pay_per_task FROM earn_levels WHERE earn_level_id = $1', [earn_level_id]);
      if (vipResult.rows.length > 0) {
        const payPerTask = parseFloat(vipResult.rows[0].pay_per_task);

        // Generate new tasks for today's remaining tasks
        const newTasks = [];
        const comments = [
          "Awesome video, really enjoyed it!",
          "This was super helpful, thank you!",
          "Great job, keep up the good work!",
          "Loved this, can't wait for more!",
          "Fantastic content, very informative.",
          "You're amazing at explaining things, thanks!",
          "Super cool video, I learned a lot!",
          "Very clear and concise, appreciate it!",
          "Exactly what I needed, thank you!",
          "This was so well done, thanks!",
          "Amazing content, keep posting more!",
          "I appreciate the effort you put into this!",
          "Really great tutorial, helped a lot!",
          "I found this really useful, thanks!",
          "This is great, thanks for sharing!",
          "Such a helpful guide, perfect timing!",
          "Thanks for this, you're awesome!",
          "Love your content, keep it up!",
          "Really appreciate the time you took on this.",
          "Great explanation, thank you!",
          "This was exactly what I was looking for.",
          "Thanks for the tips, very helpful!",
          "Great job, very well done!",
          "Your videos always make my day, thank you!",
          "Appreciate the insight, well explained!",
          "Nicely done, I really liked it.",
          "This content is gold, thank you!",
          "You made it so easy to understand, thanks!",
          "Perfect tutorial, thanks so much!",
          "Loved the energy in this video, great job!",
          "Very informative and to the point!",
          "Great share, much appreciated!",
          "Simple and effective, just what I needed.",
          "This was very well explained, thanks a lot!",
          "Such good content, love this!",
          "Always enjoy watching your videos!",
          "Thanks for making this so easy to follow!",
          "Amazing work, keep it coming!",
          "Exactly what I needed to see today!",
          "Loved the breakdown, very helpful!",
          "Great job, keep them coming!",
          "This video helped a ton, thanks!",
          "Really well done, appreciate this!",
          "Thank you for this amazing content!",
          "Your videos never disappoint!",
          "This was such a good explanation!",
          "Big thanks for sharing this!",
          "Well said and well done, thank you!",
          "Impressive, learned a lot from this.",
          "Thanks for simplifying this topic!",
          "Great content, as always!",
          "Thanks for making it so clear!",
          "Amazing, I needed this!",
          "This is super helpful, thanks!",
          "Well done, really enjoyed this.",
          "Great insights, thanks for sharing!",
          "Perfectly explained, appreciate it!",
          "So informative, thanks a bunch!",
          "You made it so easy to get, thanks!",
          "Best tutorial I've seen on this!",
          "This helped more than I thought, thanks!",
          "Always great to watch your videos!",
          "Thanks, this was super useful!",
          "Great to see content like this, thanks!",
          "Very well explained, learned a lot!",
          "Love how detailed this is, great job!",
          "Awesome, thanks for sharing!",
          "This was perfect, just what I needed!",
          "Thanks for taking the time to make this!",
          "Great video, super clear and helpful!",
          "Appreciate your hard work on this, thanks!",
          "Loved this, so well done!",
          "Really informative and easy to follow.",
          "Thanks for making this topic simpler!",
          "This was so helpful, thank you!",
          "You explained it so well, thanks!",
          "Fantastic content, much appreciated!",
          "This really cleared things up for me.",
          "You’re great at what you do, thanks!",
          "Solid video, keep it up!",
          "Very nice, this helped a lot!",
          "Thanks for this, really needed it!",
          "Good stuff, appreciate your work!",
          "Excellent content, as always!",
          "Very informative and straightforward.",
          "Thanks for making learning easy!",
          "This was super informative, thank you!",
          "Amazing, love the clarity!",
          "Thanks for the awesome content!",
          "This was very easy to understand, great job!",
          "Really appreciate this, thank you!",
          "Just what I needed, great timing!",
          "Your content always helps, thanks!",
          "Very well done, thank you!",
          "Thanks for simplifying this so well!",
          "Great tips, super useful!",
          "Thanks for making it so accessible!",
          "This was incredibly useful, thank you!",
          "Appreciate the effort in making this, thanks!",
          "Really enjoyed this, learned a lot!"
      ];



      const videoLinks = [
        "https://www.youtube.com/watch?v=_86-4XJeK5U",
        "https://www.youtube.com/watch?v=Il_UZnrVpWE",
        "https://www.youtube.com/watch?v=PEb5Szp8Qoc",
        "https://www.youtube.com/watch?v=Mt_CIBlEGos",
        "https://www.youtube.com/watch?v=qj_fqQDlboQ",
        "https://www.youtube.com/watch?v=V0LfCBYfJtw",
        "https://www.youtube.com/watch?v=ODI9gUxT1h0",
        "https://www.youtube.com/watch?v=7CBAyuFOgyc",
        "https://www.youtube.com/watch?v=_XCH6l7BzrM",
        "https://www.youtube.com/watch?v=0jTaGTDRs6E",
        "https://www.youtube.com/watch?v=dOrNiBUx6dg",
        "https://www.youtube.com/watch?v=N4z5YRdjJQ4",
        "https://www.youtube.com/watch?v=LauNsRpJNSw",
        "https://www.youtube.com/watch?v=7FDAJ8L3lig",
        "https://www.youtube.com/watch?v=4MK89zVlYdQ",
        "https://www.youtube.com/watch?v=xcvMR-4mYfk",
        "https://www.youtube.com/watch?v=EIlBlzJByKg",
        "https://www.youtube.com/watch?v=jUpknoy-DKc",
        "https://www.youtube.com/watch?v=xyktegYA62E",
        "https://www.youtube.com/watch?v=hMWv6zvC44U",
        "https://www.youtube.com/watch?v=P_1-Cpo1P0A",
        "https://www.youtube.com/watch?v=9jHVkLGFB5A",
        "https://www.youtube.com/watch?v=DcOsb0dYc84",
        "https://www.youtube.com/watch?v=FJWiI5VRc6o",
        "https://www.youtube.com/watch?v=FyJcI4UkAzs",
        "https://www.youtube.com/watch?v=igCtEmL75Fk",
        "https://www.youtube.com/watch?v=o4wZ_SBom88",
        "https://www.youtube.com/watch?v=h82OmDIJZDc",
        "https://www.youtube.com/watch?v=N9rzxpZrMz4",
        "https://www.youtube.com/watch?v=_n4nak7qpKw",
        "https://www.youtube.com/watch?v=aTV3damvdZs",
        "https://www.youtube.com/watch?v=6FYYm5I7lW0",
        "https://www.youtube.com/watch?v=zwMEhBq4kYM",
        "https://www.youtube.com/watch?v=0RUcx-Qv-K0",
        "https://www.youtube.com/watch?v=r8uFObx6zac",
        "https://www.youtube.com/watch?v=IGvG06cp2GY",
        "https://www.youtube.com/watch?v=eRbZiJOBHCg",
        "https://www.youtube.com/watch?v=52hHBkj-Ul8",
        "https://www.youtube.com/watch?v=B_8Fxv5UEMs",
        "https://www.youtube.com/watch?v=Zj9wEU2nhD0",
        "https://www.youtube.com/watch?v=omVMxK9wN_I",
        "https://www.youtube.com/watch?v=6_Py9INA4lE",
        "https://www.youtube.com/watch?v=fqxPJZ5KZA8",
        "https://www.youtube.com/watch?v=o1ExzJTFzmQ",
        "https://www.youtube.com/watch?v=8VE64XtTEQw",
        "https://www.youtube.com/watch?v=Rp3WcGRgRlA",
        "https://www.youtube.com/watch?v=pI9Vh4SNFg8",
        "https://www.youtube.com/watch?v=yB-RQhecMAc",
        "https://www.youtube.com/watch?v=qCFALTHn0CI",
        "https://www.youtube.com/watch?v=x_zBK0j9eb8"
    ];
    
      
     
      // Generate new tasks for today's remaining tasks
      for (let i = 0; i < today_remaining_tasks; i++) {
        const randomComment = comments[Math.floor(Math.random() * comments.length)];
        const videoLink = videoLinks[i % videoLinks.length]; // Cycle through the video links

        newTasks.push({
          platform: 'YouTube',
          comment: randomComment,
          link: videoLink,
          price: payPerTask
        });
      }
        // Fetch existing tasks categorized by status for the logged-in user
        const tasksResult = await pool.query(
          'SELECT task_id, user_id, task_date, pay_amount, created_at, updated_at, status FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
          [userId]
        );

        const tasks = tasksResult.rows;
        const pendingTasks = tasks.filter(task => task.status === 'pending');
        const approvedTasks = tasks.filter(task => task.status === 'approved');
        const failedTasks = tasks.filter(task => task.status === 'failed');

        res.render('earn', {
          newTasks,
          pendingTasks,
          approvedTasks,
          failedTasks
        });
      } else {
        res.status(500).send('Error fetching VIP level details. Please try again.');
      }
    } else {
      res.render('earn', { newTasks: [], pendingTasks: [], approvedTasks: [], failedTasks: [] });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading the page. Please try again.');
  }
});






// Route to generate a Solana wallet
app.get('/upgrade-vip', isAuthenticated, async (req, res) => {
  try {
      // Extract the vipLevel from the query parameters
      const vipLevel = parseInt(req.query.vipLevel, 10);

      // Log the chosen VIP level
      console.log(`User ${req.session.user.user_id} chose VIP level: ${vipLevel}`);

      if (!vipLevel || isNaN(vipLevel)) {
          console.error('Invalid VIP level received');
          return res.status(400).json({ error: 'Invalid VIP level' });
      }

      // Extract user ID from the session
      const userId = req.session.user.user_id;

      // Update the last_level_id_chosen in the users table
      await pool.query(
          'UPDATE users SET last_level_id_chosen = $1 WHERE user_id = $2',
          [vipLevel, userId]
      );
      console.log(`Updated last_level_id_chosen to ${vipLevel} for user ${userId}`);

      // Check if the wallet already exists
      const result = await pool.query(
          'SELECT public_key FROM wallets WHERE for_user_id = $1',
          [userId]
      );

      if (result.rows.length > 0) {
          // Wallet already exists, return the existing public key
          const existingPublicKey = result.rows[0].public_key;
          console.log(`Returning existing wallet for user ${userId}: ${existingPublicKey}`);
          return res.json({ publicKey: existingPublicKey });
      }

      // Generate a new Solana wallet if none exists
      const wallet = Keypair.generate();
      const publicKey = wallet.publicKey.toString();
      const privateKey = bs58.encode(wallet.secretKey); // Encode the secret key as base58

      // Save the wallet details in the database
      await pool.query(
          'INSERT INTO wallets (public_key, private_key, for_user_id, wallet_balance) VALUES ($1, $2, $3, $4)',
          [publicKey, privateKey, userId, 0.00]
      );

      console.log(`New wallet generated for user ${userId}: ${publicKey}`);

      // Respond with the new public key
      res.json({ publicKey });
  } catch (error) {
      console.error('Error generating wallet:', error);
      res.status(500).json({ error: 'Failed to generate wallet' });
  }
});


// Endpoint to fetch the current SOL to EUR exchange rate
app.get('/get-sol-eur-rate', async (req, res) => {
  try {
      const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=eur');
      if (response.data && response.data.solana && response.data.solana.eur) {
          const solToEurRate = response.data.solana.eur;
          res.json({ solToEurRate });
      } else {
          console.error('Unexpected API response:', response.data);
          res.status(500).json({ error: 'Invalid data from API' });
      }
  } catch (error) {
      console.error('Error fetching SOL to EUR rate:', error.message);
      res.status(500).json({ error: 'Failed to fetch SOL to EUR rate' });
  }
});


app.get('/check-payment', isAuthenticated, async (req, res) => {
  try {
      // Extract user ID from the session
      const userId = req.session.user.user_id;

      // Retrieve the last chosen VIP level from the users table
      const vipResult = await pool.query(
          'SELECT last_level_id_chosen FROM users WHERE user_id = $1',
          [userId]
      );

      if (vipResult.rows.length === 0 || vipResult.rows[0].last_level_id_chosen === null) {
          return res.status(404).json({ error: 'No VIP level choice found for user' });
      }

      const chosenVipLevel = vipResult.rows[0].last_level_id_chosen;
      let expectedAmountInEuros;

      console.log("Verifying payment for VIP level " + chosenVipLevel);

      // Map the chosen VIP level to the expected amount in Euros
      const vipAmountsInEur = {
          1: 100,
          2: 300,
          3: 600,
          4: 1000,
          5: 3000
      };

      expectedAmountInEuros = vipAmountsInEur[chosenVipLevel];

      if (!expectedAmountInEuros) {
          return res.status(400).json({ error: 'Invalid VIP level' });
      }

      // Fetch the current SOL-to-EUR exchange rate
      const solToEurResponse = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=eur');
      const solToEurRate = solToEurResponse.data.solana.eur;

      if (!solToEurRate) {
          throw new Error('Failed to retrieve SOL-to-EUR rate');
      }

      console.log(`SOL to EUR rate: €${solToEurRate}`);

      // Convert the expected amount in Euros to SOL
      const expectedAmountInSol = (expectedAmountInEuros / solToEurRate).toFixed(4);

      console.log(`Expected amount in SOL: ${expectedAmountInSol}`);

      // Fetch the user's wallet public key from the database
      const walletResult = await pool.query(
          'SELECT public_key FROM wallets WHERE for_user_id = $1',
          [userId]
      );

      if (walletResult.rows.length === 0) {
          return res.status(404).json({ error: 'No wallet found for the user' });
      }

      const publicKeyString = walletResult.rows[0].public_key;
      const publicKey = new PublicKey(publicKeyString);

      // Connect to the Solana cluster
      const connection = new Connection(clusterApiUrl('mainnet-beta')); // Use 'devnet' for testing

      // Get the SOL balance in lamports
      const balanceLamports = await connection.getBalance(publicKey);
      const balanceSOL = balanceLamports / 1e9; // Convert lamports to SOL (1 SOL = 1e9 lamports)

      console.log(`Balance for public key ${publicKeyString}: ${balanceSOL} SOL`);

      // Check if the balance matches or exceeds the expected amount
      if (balanceSOL >= expectedAmountInSol) {
          // Update VIP level in the database
          await pool.query(
              'UPDATE users SET earn_level_id = $1 WHERE user_id = $2',
              [chosenVipLevel, userId]
          );
          console.log(`VIP level updated to ${chosenVipLevel} for user ${userId}`);

          // Respond with success
          res.json(true); // Payment received
      } else {
          // Respond with failure
          res.json(false); // Payment not received
      }

  } catch (error) {
      console.error('Error checking wallet balance:', error);
      res.status(500).json({ error: 'Failed to check wallet balance' });
  }
});






// Route to handle task submission and update user's remaining tasks
app.post('/submit-task', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.user_id;
    const taskLink = req.body.taskLink; // Retrieve the task link from the request body
    const taskDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format

    // Query the user's VIP level
    const userResult = await pool.query('SELECT earn_level_id FROM users WHERE user_id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const vipLevelId = userResult.rows[0].earn_level_id;

    // Determine the payAmount based on earn_level_id
    let payAmount;
    switch (vipLevelId) {
      case 0:
        payAmount = 0.50;
        break;
      case 1:
        payAmount = 0.80;
        break;
      case 2:
        payAmount = 1.50;
        break;
      case 3:
        payAmount = 1.70;
        break;
      case 4:
        payAmount = 2.00;
        break;
      case 5:
        payAmount = 2.30;
        break;
      default:
        payAmount = 0; // fallback value if the VIP level is unexpected
    }

    // Generate a unique 6-digit task ID
    const uniqueTaskId = await generateUniqueTaskId();

    // Set the time zone to Greece (Europe/Athens)
    await pool.query("SET TIME ZONE 'Europe/Athens'");

    // Insert task into the 'tasks' table with current timestamp and task link
    const result = await pool.query(
      'INSERT INTO tasks (task_id, user_id, task_date, pay_amount, created_at, updated_at, status, task_link) VALUES ($1, $2, NOW(), $3, NOW(), NOW(), $4, $5) RETURNING *',
      [uniqueTaskId, userId, payAmount, 'pending', taskLink]
    );

    // Update 'today_remaining_tasks' in the 'users' table
    await pool.query(
      'UPDATE users SET today_remaining_tasks = today_remaining_tasks - 1 WHERE user_id = $1',
      [userId]
    );

    // Send the newly created task data back to the client
    res.status(200).json({ task: result.rows[0], message: 'Task submitted successfully!' });
  } catch (err) {
    console.error('Error inserting task:', err);
    res.status(500).json({ message: 'Error submitting the task. Please try again.' });
  }
});


app.get('/page/profile', isAuthenticated, async (req, res) => {
  try {
    console.log("kalese to profile");

    const userId = req.session.user.user_id;

    // Query to fetch the most recent profile information from the `users` table
    const userResult = await pool.query(
      'SELECT * FROM users WHERE user_id = $1',
      [userId]
    );

    // Check if the user was found
    if (userResult.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const userProfile = userResult.rows[0];

    // Optionally: Update session data if necessary (if email, balance, etc. was changed)
    req.session.user.email = userProfile.email; // Update session data with the new email
    req.session.user.balance = userProfile.balance; // Update session data with the new balance

    // Query to fetch users invited by this user, handling null cases in refCodeInvitedBy
    let invitedUsers = [];
    if (userProfile.refCodeInvite) {
      const invitedUsersResult = await pool.query(
        'SELECT email, created_at FROM users WHERE "refCodeInvitedBy" = $1',
        [userProfile.refCodeInvite]
      );
      invitedUsers = invitedUsersResult.rows;
    }

    // Render the profile page and pass the updated user profile and invited users data
    res.render('profile', {
      user: {
        email: userProfile.email,
        balance: userProfile.balance,
        earn_level_id: userProfile.earn_level_id,
        refCodeInvite: userProfile.refCodeInvite,
        created_at: userProfile.created_at, // Pass as-is from the database
        invitedUsers: invitedUsers
      }
    });
    console.log("eftase ws edw sto profile");
  } catch (error) {
    console.error('Error fetching profile data:', error);
    res.status(500).send('Internal Server Error');
  }
});




// Route for dynamically loading other pages
app.get('/page/:page', isAuthenticated, (req, res) => {
  const { page } = req.params;
  console.log('Requested page:', page); // Debugging

  const validPages = ['home','earn','profile', 'vip'];
  if (validPages.includes(page)) {
    res.render(page, { user: req.session.user });
  } else {
    res.status(404).send('Page not found');
  }
});

// 404 route for unmatched paths
app.use((req, res) => {
  res.status(404).send('Page not found');
});




// Start the server
app.listen(port, HOST, () => {
  console.log(`Server running at http://${HOST}:${port}`);
  // updateStatusToApproved();
  // Call the update function every 5 minutes (300,000 ms)
    setInterval(updateStatusToApproved, 120000); // Calls the function every 2 minutes
});









// Function to update the status column to "approved" at random intervals
async function updateStatusToApproved() {
  try {
    // Fetch the total number of tasks
    const res = await pool.query('SELECT COUNT(*) AS total FROM tasks');
    const totalTasks = parseInt(res.rows[0].total, 10);

    if (totalTasks > 0) {
      const interval = 300000 / totalTasks; // Total 5 minutes (300,000 ms) divided by number of tasks

      // Fetch all task IDs with the associated user_id and pay_amount
      const taskIdsRes = await pool.query('SELECT task_id, user_id, pay_amount, status FROM tasks');
      const tasks = taskIdsRes.rows; // Get an array of tasks with user_id, pay_amount, and status

      for (let i = 0; i < tasks.length; i++) {
        const task = tasks[i];
        const { task_id, user_id, pay_amount, status } = task;

        // Skip the task if it is already approved
        if (status === 'approved') {
          console.log(`Task ID ${task_id} is already approved. Skipping.`);
          continue;
        }

        // Update the task status to "approved"
        await pool.query('UPDATE tasks SET status = $1 WHERE task_id = $2', ['approved', task_id]);
        console.log(`Updated task ID ${task_id} to status "approved".`);

        // Update the user balance
        await pool.query(
          'UPDATE users SET balance = balance + $1 WHERE user_id = $2',
          [pay_amount, user_id]
        );
        console.log(`Updated user ID ${user_id}'s balance by adding ${pay_amount}.`);

        // Wait for the interval before updating the next task
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    } else {
      console.log('No tasks found in the table.');
    }
  } catch (error) {
    console.error('Error updating task status:', error);
  }
}












