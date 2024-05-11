import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import pgSession from "connect-pg-simple";
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import bcrypt from 'bcrypt';
import env from 'dotenv';


const app = express();
const port = 5000;
env.config();

// const saltRounds = 10;
// const plainPassword = '1234';

// bcrypt.hash(plainPassword, saltRounds, (err, hash) => {
//   if (err) {
//     console.error('Error hashing password:', err);
//   } else {
//     console.log('Hashed password:', hash);
//   }
// });

// Database connection
const db = new pg.Client({
  user: process.env.CLIENT_DB_USER,
  host: process.env.CLIENT_DB_HOST,
  database: process.env.CLIENT_DB_DATABASE,
  password: process.env.CLIENT_DB_PASSWORD,
  port: process.env.CLIENT_DB_PORT,
  ssl: {
    rejectUnauthorized: false, // Disables SSL/TLS certificate verification (use only for testing)
  }
});
db.connect();

// Session configuration
const pgSessionStore = pgSession(session);
app.use(session({
  store: new pgSessionStore({
    pool: db,
    tableName: process.env.PG_SESSION_TABLENAME
  }),
  secret: process.env.PG_SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));

// Static files middleware
app.use(express.static("public"));
app.use(express.json());

//Email Robot
// Create a nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.NODEMAILER_HOST,
  port: process.env.NODEMAILER_PORT,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: process.env.NODEMAILER_USER,
    pass: process.env.NODEMAILER_PASS,
  },
});

const EMAIL_SECRET = process.env.NODEMAILER_SECRET; // Replace with a strong secret

// Routes
app.get("/", (req, res) => {
  res.render("welcome.ejs");
});

app.get("/getquote", (req, res) => {
  res.render("getquote.ejs");
});

app.get("/learnmore", (req, res) => {
  res.render("learnmore.ejs");
});

app.get("/gallery", (req, res) => {
  res.render("gallery.ejs");
});

app.get("/forgotpassword", (req, res) => {
  res.render("forgotpassword.ejs");
});

app.get("/login", (req, res) => {
  let accountNotVerified = false;
  let userNotFound = false;
  let wrongPass = false;

  // Check if account not verified flag is set
  if (req.session.accountNotVerified) {
    accountNotVerified = true;
    // Clear the flag from the session
    delete req.session.accountNotVerified;
  }

  // Check if user not found flag is set
  if (req.session.userNotFound) {
    userNotFound = true;
    // Clear the flag from the session
    delete req.session.userNotFound;
  }

  // Check if user not found flag is set
  if (req.session.wrongPass) {
    wrongPass = true;
    // Clear the flag from the session
    delete req.session.wrongPass;
  }

  // Render login page with appropriate span visibility
  res.render("login.ejs", { accountNotVerified, userNotFound, wrongPass });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      if (!user.jwt_verified) {
        // Check if user has been jwt_verified
        // Instead of sending a response, set a flag to indicate account not verified
        req.session.accountNotVerified = true;
        return res.redirect("/login"); // Redirect back to login page
      }
      
      // Verify password using bcrypt
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        req.session.user = user;
        req.session.userId = user.id; // Set the user ID in the session
        res.redirect("/Logged-In/dashboard");
      } else {
        req.session.wrongPass = true;
        return res.redirect("/login"); // Redirect back to login page
      }
    } else {
      req.session.userNotFound = true;
      return res.redirect("/login"); // Redirect back to login page
    }
  } catch (err) {
    console.error(err);
    alert("An error occurred");
  }
});

//Forgot Password Email Sending
// Function to generate a unique token
function generateToken(email) {
  return jwt.sign({ email }, EMAIL_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour
}

// Route to handle forgot password request
app.post('/forgotpassword', async (req, res) => {
  const { email } = req.body;

  try {
    // Query to check if the email exists in the users table
    const queryResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);

    if (queryResult.rows.length > 0) {
      // Generate a unique token
      const token = generateToken(email);

      // Email exists, send reset password link with token
      const mailOptions = {
        from: process.env.NODEMAILER_USER,
        to: email,
        subject: 'Password Reset Instructions',
        text: 'Click here to reset your password.',
        html: `<p>Click <a href="http://www.keepupwork.com/changepassword/${token}">here</a> to reset your password</p>`
      };

      // Send mail
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          res.redirect('/');
        } else {
          console.log('Email sent:', info.response);
          res.redirect('/');
        }
      });
    } else {
      // Email does not exist
      res.redirect('/');
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Middleware to check token validity and expiration
// Middleware to check token validity and expiration
app.use('/changepassword/:token', (req, res, next) => {
  const { token } = req.params;

  jwt.verify(token, EMAIL_SECRET, (err, decoded) => {
    if (err) {
      res.status(401).send('Unauthorized'); // Token is invalid
    } else {
      // Assign decoded email directly to req.email
      req.email = decoded.email; // Attach decoded email to request object
      next(); // Token is valid, proceed to the next middleware
    }
  });
});

// Route to handle rendering the changepassword page
app.get('/changepassword/:token', (req, res) => {
  const { token } = req.params;
  const { email } = req; // Access email from request object

  // Pass email to the view or perform any necessary operations
  res.render("changepassword.ejs", { email }); // Render the changepassword page with email
});

//Change Forgotten Password
app.post('/changepassword', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Encrypt password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

    // Update password in the database
    await db.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    console.log('Password updated successfully');
    res.redirect('/');
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('Error updating password');
  }
});

//Email Verification Page
app.get("/verification", (req, res) => {
  res.render("verification1.ejs");
});

app.get("/confirmation", (req, res) => {
  // Retrieve user information from query parameters
  const { fname, lname, email } = req.query;

  // Render the confirmation page with user information
  res.render("confirmation.ejs", { fname, lname, email });
});

//Role Selection
app.post('/assignRole', async (req, res) => {
  const { email, role } = req.body;

  try {
      // Update the user's role in the database
      await db.query('UPDATE users SET role = $1 WHERE email = $2', [role, email]);

      req.session.user.role = role;
      res.status(200).send('Role assigned successfully');
  } catch (error) {
      console.error('Error assigning role:', error);
      alert("Error assigning role");
  }
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.post("/signup", async (req, res) => {
  const { fName, lName, email, password, CompCode } = req.body;

  try {
    // Check if the email already exists in the database
    const checkEmailResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkEmailResult.rows.length > 0) {
      return alert("Email already exists. Try logging in.");
    }

    // Check if the company code exists in the companycodes table
    const checkCodeResult = await db.query("SELECT * FROM companycodes WHERE compcode = $1", [CompCode]);
    if (checkCodeResult.rows.length === 0) {
      return alert("Invalid company code. Please enter a valid code.");
    }

    const { admin_email: adminEmail, companyname: companyName } = checkCodeResult.rows[0]; // Get admin email and company name

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const insertUserResult = await db.query(
      "INSERT INTO users (fName, lName, email, password, company) VALUES ($1, $2, $3, $4, $5)",
      [fName, lName, email, hashedPassword, companyName]
    );

    // Generate a JWT token for email verification
    const token = jwt.sign({ email, fName, lName }, EMAIL_SECRET, { expiresIn: '1d' }); // Pass fName and lName along with email

    // Send verification email to the administrator
    await transporter.sendMail({
      from: 'keepupauto@gmail.com',
      to: adminEmail, // Use the admin email retrieved from the database
      subject: 'New User Signup - Verification Required',
      html: `
        <p>A new user has signed up to join your KeepUp team. Please verify their account:</p>
        <p>Name: ${fName} ${lName}</p>
        <p>Email: ${email}</p>
        <p>Company: ${companyName}</p>
        <p>Click <a href="http://www.keepupwork.com/confirmation/${token}">here</a> to verify the user.</p>
      `,
    });

    req.session.user = { fName, lName, email };
    res.redirect("/verification");
  } catch (err) {
    console.error("Error signing up:", err);
    alert("There seems to have been an error. Please contact KeepUp team.");
  }
});

app.get('/confirmation/:token', async (req, res) => {
  try {
    const { token } = req.params;
    // Verify the token
    const { email, fName, lName } = jwt.verify(token, EMAIL_SECRET); // Retrieve fName and lName from the token

    // Update the user record in the database to mark as verified
    await db.query('UPDATE users SET jwt_verified = true WHERE email = $1', [email]);

    // Redirect to the confirmation page and pass user details as query parameters
    res.redirect(`http://keepupwork.com/confirmation?fname=${fName}&lname=${lName}&email=${email}`);
  } catch (e) {
    // Handle token verification error
    console.error(e);
    alert('Invalid or expired token');
  }
});

app.get('/confirmation2', (req, res) => {
  const { role } = req.session.user;
  const { fname, lname } = req.query;
   // Assuming you stored user info in session
  res.render('confirmation2.ejs', { fname, lname, role });
});

app.get("/Logged-In/*", (req, res, next) => {
  if (!req.session.user) {
    res.redirect("/login");
  } else {
    next();
  }
});

//User data for all web pages
const fetchUserData = (req, res, next) => {
  const userId = req.session.user.id; // Assuming you store user ID in session
  // Query the database to fetch user's name and role based on userId
  db.query('SELECT fname, lname, role FROM users WHERE id = $1', [userId], (err, result) => {
    if (err) {
      console.error('Error fetching user data:', err);
      res.locals.userData = { fname: '', lname: '', role: '' }; // Set user's data to default values in case of error
    } else {
      const user = result.rows[0];
      res.locals.userData = {
        fname: user ? user.fname : '',
        lname: user ? user.lname : '',
        role: user ? user.role : ''
      }; // Store user's data in res.locals
    }
    next(); // Call next middleware
  });
};

// Apply the middleware to all routes within the /Logged-In directory
app.use("/Logged-In/*", fetchUserData);

app.get("/Logged-In/tutorial-addproject", (req, res) => {
  res.render("Logged-In/tutorial-addproject.ejs", { currentPage: "help" });
});

app.get("/Logged-In/tutorial-editproject", (req, res) => {
  res.render("Logged-In/tutorial-editproject.ejs", { currentPage: "help" });
});

app.get("/Logged-In/tutorial-faq", (req, res) => {
  res.render("Logged-In/tutorial-faq.ejs", { currentPage: "help" });
});

app.get("/Logged-In/editpassword", (req, res) => {
  try {
    // Retrieve the user's email from the session
    const userEmail = req.session.user.email;

    // Render the "editpassword.ejs" template, passing the user's email and the current page
    res.render("Logged-In/editpassword.ejs", { currentPage: "settings", userEmail: userEmail });
  } catch (error) {
    // Handle any errors that may occur
    console.error("Error rendering editpassword page:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post('/editpassword', async (req, res) => {
  try {
    // Extract email and password from the request body
    const { email, password } = req.body;

    // Encrypt the new password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

    // Update the user's password in the database
    await db.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    // Password updated successfully
    console.log('Password updated successfully for user with email:', email);
    res.redirect('/Logged-In/settings?successMessage=Password%20changed%20successfully');
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('Error updating password');
  }
});

app.get("/Logged-In/addproject", (req, res) => {
  res.render("Logged-In/addproject.ejs", { currentPage: "addproject" });
});

// Add A Project
app.post("/addproject", async (req, res) => {
  const { project_name, contractor_email, cosd, a1, a2, a3, a4, a5, b1, b2, b3, c1, c2, c3, d1, d2, d3, d4, d5, d6, d7, e1, e2, e3, f1, f2, confirmed, drn, stc, drv } = req.body;
  const user_email = req.session.user.email;

  try {
    // Retrieve the user's company from the user table
    const { rows: [{ company }] } = await db.query("SELECT company FROM users WHERE email = $1", [user_email]);

    // Handle optional STC and DRV values
    const stcValue = stc === "STC" ? null : stc;
    const drvValue = drv === "DRV" ? null : drv;

    // Insert the project into the projects table, including the user's company
    await db.query(
      "INSERT INTO projects (project_name, contractor_email, cosd, a1, a2, a3, a4, a5, b1, b2, b3, c1, c2, c3, d1, d2, d3, d4, d5, d6, d7, e1, e2, e3, f1, f2, user_email, company, drn, stc, drv, date_created) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, CURRENT_TIMESTAMP)",
      [project_name, contractor_email, cosd, a1, a2, a3, a4, a5, b1, b2, b3, c1, c2, c3, d1, d2, d3, d4, d5, d6, d7, e1, e2, e3, f1, f2, user_email, company, drn, stcValue, drvValue]
    );

    // Redirect the user to contactemail if the form was submitted after confirmation
    if (confirmed === 'true') {
      res.redirect(`/Logged-In/contactemail?project_name=${encodeURIComponent(project_name)}&contractor_email=${encodeURIComponent(contractor_email)}`);
    } else {
      res.redirect("/Logged-In/myprojects");
    }
  } catch (error) {
    console.error("Error adding project:", error);
    alert("Error adding project");
  }
});

//Auto initial Contact Email
app.get("/Logged-In/contactemail", async (req, res) => {
  try {
    const { project_name, contractor_email } = req.query; // Fetching from query parameters
    const user_email = req.session.user.email;

    // Fetch company name from users table
    const userQuery = await db.query("SELECT company FROM users WHERE email = $1", [user_email]);
    const companyName = userQuery.rows[0].company;

    // Fetch project details including drn, stc, and drv
    const projectQuery = await db.query("SELECT drn, stc, drv FROM projects WHERE project_name = $1 AND contractor_email = $2", [project_name, contractor_email]);
    const { drn, stc, drv } = projectQuery.rows[0]; // Assuming there's only one project with the same name and email

    // Fetch users with the same company name excluding the current user and those who are not jwt_verified
    const companyUsersQuery = await db.query("SELECT id, fname, lname, email FROM users WHERE company = $1 AND email != $2 AND jwt_verified = true", [companyName, user_email]);
    const companyUsers = companyUsersQuery.rows;

    // Determine the greeting based on the current time
    const currentTime = new Date().getHours();
    const greeting = currentTime < 12 ? "Good morning" : "Good afternoon";

    // Render contactemail.ejs with project details and company users
    res.render("Logged-In/contactemail.ejs", {
      currentPage: "addproject",
      project_name: project_name,
      contractor_email: contractor_email,
      company_name: companyName,
      user_email: user_email,
      company_users: companyUsers,
      greeting: greeting,
      drn: drn,
      stc: stc,
      drv: drv
    });
  } catch (error) {
    console.error("Error fetching project details:", error);
    alert("Error fetching project details");
  }
});

//Send Auto Initial Contact Email
const upload = multer({ dest: 'uploads/' });

app.post("/send-email", upload.array('attachment', 3), async (req, res) => {
  try {
    const { to, cc, subject, body } = req.body;

    // Check if files were uploaded
    let attachments = [];

    // Loop through uploaded files and push them to the attachments array
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        attachments.push({
          filename: file.originalname,
          path: file.path
        });
      });
    }

    // Update the database to set 'a1' as true for the specified project_name
    await db.query(
      "UPDATE projects SET a1 = true WHERE project_name = $1",
      [req.body.project_name]
    );

    // Sending email
    await transporter.sendMail({
      from: 'keepupauto@gmail.com',
      to: to,
      cc: cc,
      subject: subject,
      text: body,
      html: '<p>' + body.replace(/\n/g, '<br>') + '</p>',
      attachments: attachments
    });

    res.redirect("/Logged-In/myprojects");
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).send("Error sending email");
  }
});

// Define route to render welcome.ejs
app.get("/welcome", (req, res) => {
  res.render("welcome.ejs");
});

//Get user info to all web pages



//Dashboard Table
let projects = [];

app.get("/Logged-In/dashboard", async (req, res) => {
  try {
    const user_company = req.session.user.company; // Get the current user's company

    const result = await db.query(`
      SELECT 
        p.project_name, 
        p.contractor_email,
        ROUND((
          (CASE WHEN p.a1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a4 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a5 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d4 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d5 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d6 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d7 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.f1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.f2 THEN 1 ELSE 0 END)
      ) * 1.0 / (
          CASE
              WHEN p.stc IS NULL AND p.drv IS NULL THEN 21
              WHEN p.stc IS NOT NULL AND p.drv IS NULL THEN 22
              WHEN p.stc IS NULL AND p.drv IS NOT NULL THEN 22
              ELSE 23
          END
      ) * 100, 0) AS checked_percentage,                  
        (
            CASE
                WHEN p.a1 IS NULL THEN 'a1'
                WHEN p.a2 IS NULL THEN 'a2'
                WHEN p.a3 IS NULL THEN 'a3'
                WHEN p.b1 IS NULL THEN 'b1'
                WHEN p.b2 IS NULL THEN 'b2'
                WHEN p.b3 IS NULL THEN 'b3'
                WHEN p.c1 IS NULL THEN 'c1'
                WHEN p.c2 IS NULL THEN 'c2'
                WHEN p.c3 IS NULL THEN 'c3'
                WHEN p.d1 IS NULL THEN 'd1'
                WHEN p.d2 IS NULL THEN 'd2'
                WHEN p.d3 IS NULL THEN 'd3'
                WHEN p.d4 IS NULL THEN 'd4'
                WHEN p.d5 IS NULL THEN 'd5'
                WHEN p.d6 IS NULL THEN 'd6'
                WHEN p.d7 IS NULL THEN 'd7'
                WHEN p.e1 IS NULL THEN 'e1'
                WHEN p.e2 IS NULL THEN 'e2'
                WHEN p.e3 IS NULL THEN 'e3'
                WHEN p.f1 IS NULL THEN 'f1'
                WHEN p.f2 IS NULL THEN 'f2'
                ELSE NULL
            END
        ) AS first_null_column,
        TO_CHAR(p.cosd, 'MM/DD/YY') AS cosd,
        TO_CHAR(p.edit_timestamp, 'MM/DD/YY') AS edit_timestamp,
        CONCAT(u.fname, ' ', LEFT(u.lname, 1), '.') AS running_by,
        p.drn, p.stc, p.drv, -- Fetch drn, stc, drv values
        p.a4, p.a5 -- Fetch a4 and a5 values
      FROM projects p
      INNER JOIN users u ON p.user_email = u.email -- Join projects and users table based on user_email
      WHERE u.company = $1; -- Filter projects by user's company
    `, [user_company]);

    const projects = result.rows;

    res.render("Logged-In/dashboard.ejs", {
      listProjects: projects,
      currentPage: "dashboard"
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

//myprojects Table
app.get("/Logged-In/myprojects", async (req, res) => {
  const user_email = req.session.user.email;
  let projectNotFound = req.session.projectNotFound || false;
  let incorrectPassword = req.session.incorrectPassword || false;

  // Clear session flags after retrieving their values
  req.session.projectNotFound = false;
  req.session.incorrectPassword = false;

  try {
    const result = await db.query(`
      SELECT 
        project_name, 
        contractor_email,
        drn,  -- Include drn column
        stc,  -- Include stc column
        drv,  -- Include drv column
        ROUND((
          (CASE WHEN a1 THEN 1 ELSE 0 END) + 
          (CASE WHEN a2 THEN 1 ELSE 0 END) + 
          (CASE WHEN a3 THEN 1 ELSE 0 END) + 
          (CASE WHEN a4 THEN 1 ELSE 0 END) + 
          (CASE WHEN a5 THEN 1 ELSE 0 END) + 
          (CASE WHEN b1 THEN 1 ELSE 0 END) + 
          (CASE WHEN b2 THEN 1 ELSE 0 END) + 
          (CASE WHEN b3 THEN 1 ELSE 0 END) + 
          (CASE WHEN c1 THEN 1 ELSE 0 END) + 
          (CASE WHEN c2 THEN 1 ELSE 0 END) + 
          (CASE WHEN c3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d1 THEN 1 ELSE 0 END) + 
          (CASE WHEN d2 THEN 1 ELSE 0 END) + 
          (CASE WHEN d3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d4 THEN 1 ELSE 0 END) + 
          (CASE WHEN d5 THEN 1 ELSE 0 END) + 
          (CASE WHEN d6 THEN 1 ELSE 0 END) + 
          (CASE WHEN d7 THEN 1 ELSE 0 END) + 
          (CASE WHEN e1 THEN 1 ELSE 0 END) + 
          (CASE WHEN e2 THEN 1 ELSE 0 END) + 
          (CASE WHEN e3 THEN 1 ELSE 0 END) + 
          (CASE WHEN f1 THEN 1 ELSE 0 END) + 
          (CASE WHEN f2 THEN 1 ELSE 0 END)
      ) * 1.0 / (
          CASE
              WHEN stc IS NULL AND drv IS NULL THEN 21
              WHEN stc IS NOT NULL AND drv IS NULL THEN 22
              WHEN stc IS NULL AND drv IS NOT NULL THEN 22
              ELSE 23
          END
      ) * 100, 0) AS checked_percentage,
        (
          CASE
            WHEN a1 IS NULL THEN 'a1'
            WHEN a2 IS NULL THEN 'a2'
            WHEN a3 IS NULL THEN 'a3'
            WHEN b1 IS NULL THEN 'b1'
            WHEN b2 IS NULL THEN 'b2'
            WHEN b3 IS NULL THEN 'b3'
            WHEN c1 IS NULL THEN 'c1'
            WHEN c2 IS NULL THEN 'c2'
            WHEN c3 IS NULL THEN 'c3'
            WHEN d1 IS NULL THEN 'd1'
            WHEN d2 IS NULL THEN 'd2'
            WHEN d3 IS NULL THEN 'd3'
            WHEN d4 IS NULL THEN 'd4'
            WHEN d5 IS NULL THEN 'd5'
            WHEN d6 IS NULL THEN 'd6'
            WHEN d7 IS NULL THEN 'd7'
            WHEN e1 IS NULL THEN 'e1'
            WHEN e2 IS NULL THEN 'e2'
            WHEN e3 IS NULL THEN 'e3'
            WHEN f1 IS NULL THEN 'f1'
            WHEN f2 IS NULL THEN 'f2'
            ELSE NULL
          END
        ) AS first_null_column,
        TO_CHAR(cosd, 'MM/DD/YY') AS cosd,
        TO_CHAR(edit_timestamp, 'MM/DD/YY') AS edit_timestamp 
      FROM projects
      WHERE user_email = $1
      ORDER BY edit_timestamp DESC
    `, [user_email]);

    const projects = result.rows;

    res.render("Logged-In/myprojects.ejs", {
      listProjects: projects,
      currentPage: "myprojects",
      projectNotFound, 
      incorrectPassword, 
    });
  } catch (error) {
    console.error("Error fetching projects:", error);
    alert("Error fetching projects");
  }
});

//Active Projects Table
app.get("/Logged-In/activeprojects", async (req, res) => {
  try {
    const user_company = req.session.user.company; // Get the current user's company

    const result = await db.query(`
      SELECT 
        p.project_name, 
        p.contractor_email,
        p.drn,  -- Include drn column
        p.stc,  -- Include stc column
        p.drv,  -- Include drv column
        ROUND((
          (CASE WHEN p.a1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a4 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.a5 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.b3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.c3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d4 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d5 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d6 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.d7 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e2 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.e3 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.f1 THEN 1 ELSE 0 END) + 
          (CASE WHEN p.f2 THEN 1 ELSE 0 END)
      ) * 1.0 / (
          CASE
              WHEN p.stc IS NULL AND p.drv IS NULL THEN 21
              WHEN p.stc IS NOT NULL AND p.drv IS NULL THEN 22
              WHEN p.stc IS NULL AND p.drv IS NOT NULL THEN 22
              ELSE 23
          END
      ) * 100, 0) AS checked_percentage,
        (
          CASE
            WHEN p.a1 IS NULL THEN 'a1'
            WHEN p.a2 IS NULL THEN 'a2'
            WHEN p.a3 IS NULL THEN 'a3'
            WHEN p.b1 IS NULL THEN 'b1'
            WHEN p.b2 IS NULL THEN 'b2'
            WHEN p.b3 IS NULL THEN 'b3'
            WHEN p.c1 IS NULL THEN 'c1'
            WHEN p.c2 IS NULL THEN 'c2'
            WHEN p.c3 IS NULL THEN 'c3'
            WHEN p.d1 IS NULL THEN 'd1'
            WHEN p.d2 IS NULL THEN 'd2'
            WHEN p.d3 IS NULL THEN 'd3'
            WHEN p.d4 IS NULL THEN 'd4'
            WHEN p.d5 IS NULL THEN 'd5'
            WHEN p.d6 IS NULL THEN 'd6'
            WHEN p.d7 IS NULL THEN 'd7'
            WHEN p.e1 IS NULL THEN 'e1'
            WHEN p.e2 IS NULL THEN 'e2'
            WHEN p.e3 IS NULL THEN 'e3'
            WHEN p.f1 IS NULL THEN 'f1'
            WHEN p.f2 IS NULL THEN 'f2'
            ELSE NULL
          END
        ) AS first_null_column,
        TO_CHAR(p.cosd, 'MM/DD/YY') AS cosd,
        TO_CHAR(p.edit_timestamp, 'MM/DD/YY') AS edit_timestamp,
        CONCAT(u.fname, ' ', LEFT(u.lname, 1), '.') AS running_by
      FROM projects p
      INNER JOIN users u ON p.user_email = u.email -- Join on user_email column
      WHERE u.company = $1; -- Filter projects by user's company
    `, [user_company]);

    const projects = result.rows;

    res.render("Logged-In/activeprojects.ejs", {
      listProjects: projects,
      currentPage: "activeprojects"
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/Logged-In/dashboard", (req, res) => {
  // Handle rendering the dashboard page
  res.render("dashboard.ejs");
});

//EDIT PROJECT
app.get("/Logged-In/editproject", async (req, res) => {
  const userId = req.session.user.id;
  const projectName = req.query.projectName; // Get the project name from the query parameter

  let projectNotFound = false;
  let errorFetchingProjectDetails = false;
  let userNotFound = false;
  let incorrectPassword = false;
  let errorDeletingProject = false;

  try {
    // Fetch company name from the session user's email
    const user_email = req.session.user.email;
    const userQuery = await db.query("SELECT company FROM users WHERE email = $1", [user_email]);
    const companyName = userQuery.rows[0].company;

    // Fetch users with the same company name excluding the current user and those who are not jwt_verified
    const companyUsersQuery = await db.query("SELECT id, fname, lname, email FROM users WHERE company = $1 AND email != $2 AND jwt_verified = true", [companyName, user_email]);
    const companyUsers = companyUsersQuery.rows;

    const result = await db.query(`
      SELECT 
        a1, a2, a3, 
        b1, b2, b3, 
        c1, c2, c3, 
        d1, d2, d3, d4, d5, d6, d7, 
        e1, e2, e3, 
        f1, f2, contractor_email, user_email,
        drn, stc, drv,
        ROUND((
          (CASE WHEN a1 THEN 1 ELSE 0 END) + 
          (CASE WHEN a2 THEN 1 ELSE 0 END) + 
          (CASE WHEN a3 THEN 1 ELSE 0 END) + 
          (CASE WHEN a4 THEN 1 ELSE 0 END) + 
          (CASE WHEN a5 THEN 1 ELSE 0 END) + 
          (CASE WHEN b1 THEN 1 ELSE 0 END) + 
          (CASE WHEN b2 THEN 1 ELSE 0 END) + 
          (CASE WHEN b3 THEN 1 ELSE 0 END) + 
          (CASE WHEN c1 THEN 1 ELSE 0 END) + 
          (CASE WHEN c2 THEN 1 ELSE 0 END) + 
          (CASE WHEN c3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d1 THEN 1 ELSE 0 END) + 
          (CASE WHEN d2 THEN 1 ELSE 0 END) + 
          (CASE WHEN d3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d4 THEN 1 ELSE 0 END) + 
          (CASE WHEN d5 THEN 1 ELSE 0 END) + 
          (CASE WHEN d6 THEN 1 ELSE 0 END) + 
          (CASE WHEN d7 THEN 1 ELSE 0 END) + 
          (CASE WHEN e1 THEN 1 ELSE 0 END) + 
          (CASE WHEN e2 THEN 1 ELSE 0 END) + 
          (CASE WHEN e3 THEN 1 ELSE 0 END) + 
          (CASE WHEN f1 THEN 1 ELSE 0 END) + 
          (CASE WHEN f2 THEN 1 ELSE 0 END)
      ) * 1.0 / (
          CASE
              WHEN stc IS NULL AND drv IS NULL THEN 21
              WHEN stc IS NOT NULL AND drv IS NULL THEN 22
              WHEN stc IS NULL AND drv IS NOT NULL THEN 22
              ELSE 23
          END
      ) * 100, 0) AS checked_percentage,
        TO_CHAR(cosd, 'MM/DD/YY') AS cosd,
        TO_CHAR(edit_timestamp, 'MM/DD/YY') AS edit_timestamp 
      FROM projects
      WHERE project_name = $1
    `, [projectName]);

    // Check if the result contains data
    if (result.rows.length > 0) {
      const project = result.rows[0];
      res.render("Logged-In/editproject.ejs", { 
        projectName: projectName,
        project: project,
        currentPage: "myprojects",
        userId: userId,
        company_users: companyUsers, // Pass company users to the template
        projectNotFound, 
        errorFetchingProjectDetails, 
        userNotFound, 
        incorrectPassword, 
        errorDeletingProject
      });
    } else {
      // If no data found for the project name, set appropriate flags
      req.session.projectNotFound = true;
      return res.redirect("/Logged-In/myprojects");
    }
  } catch (error) {
    console.error("Error fetching project details:", error);
    // Set appropriate flags for error scenarios
    req.session.errorFetchingProjectDetails = true;
    return res.redirect("/Logged-In/myprojects");
  }
});

// Edit Project Name and Email
app.post("/Logged-In/editproject", async (req, res) => {
  const projectName = req.body.projectName; // Get the original project name
  const updatedProjectName = req.body.updatedProjectName;
  const updatedContractorEmail = req.body.updatedContractorEmail;
  let updatedDrn = req.body.updateddrn; // Get the updated DRN value
  let updatedStc = req.body.updatedstc; // Get the updated STC value
  let updatedDrv = req.body.updateddrv; // Get the updated DRV value

  // Check if the values are empty strings and set them to null
  updatedDrn = updatedDrn.trim() !== "" ? updatedDrn : null;
  updatedStc = updatedStc.trim() !== "" ? updatedStc : null;
  updatedDrv = updatedDrv.trim() !== "" ? updatedDrv : null;

  try {
    await db.query("UPDATE projects SET project_name = $1, contractor_email = $2, drn = $3, stc = $4, drv = $5 WHERE project_name = $6", [updatedProjectName, updatedContractorEmail, updatedDrn, updatedStc, updatedDrv, projectName]);
    res.redirect("/Logged-In/editproject?projectName=" + updatedProjectName);
  } catch (error) {
    console.error("Error updating project details:", error);
    alert("Error updating project details");
  }
});

// Project Checks Edit
app.post("/Logged-In/editchecks", (req, res) => {
  const checkboxName = req.body.checkboxName;
  const isChecked = req.body.isChecked;
  const projectName = req.body.projectName;

  // Get the current timestamp
  const currentTimestamp = new Date();

  // Construct the SQL query
  const query = `
    UPDATE projects
    SET ${checkboxName} = $1, edit_timestamp = $2
    WHERE project_name = $3
  `;

  // Execute the SQL query with parameters
  db.query(query, [isChecked, currentTimestamp, projectName], (err, result) => {
    if (err) {
      console.error("Error updating project checks:", err);
      alert("Error updating project checks");
    } else {
      // Send response to indicate success
      res.sendStatus(200);
    }
  });
});

//viewprojects
app.get("/Logged-In/viewproject", async (req, res) => {
  const userId = req.session.user.id;
  const projectName = req.query.projectName; // Get the project name from the query parameter
  try {
    const result = await db.query(`
      SELECT 
        a1, a2, a3, 
        b1, b2, b3, 
        c1, c2, c3, 
        d1, d2, d3, d4, d5, d6, d7, 
        e1, e2, e3, 
        f1, f2, contractor_email,
        ROUND((
          (CASE WHEN a1 THEN 1 ELSE 0 END) + 
          (CASE WHEN a2 THEN 1 ELSE 0 END) + 
          (CASE WHEN a3 THEN 1 ELSE 0 END) + 
          (CASE WHEN a4 THEN 1 ELSE 0 END) + 
          (CASE WHEN a5 THEN 1 ELSE 0 END) + 
          (CASE WHEN b1 THEN 1 ELSE 0 END) + 
          (CASE WHEN b2 THEN 1 ELSE 0 END) + 
          (CASE WHEN b3 THEN 1 ELSE 0 END) + 
          (CASE WHEN c1 THEN 1 ELSE 0 END) + 
          (CASE WHEN c2 THEN 1 ELSE 0 END) + 
          (CASE WHEN c3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d1 THEN 1 ELSE 0 END) + 
          (CASE WHEN d2 THEN 1 ELSE 0 END) + 
          (CASE WHEN d3 THEN 1 ELSE 0 END) + 
          (CASE WHEN d4 THEN 1 ELSE 0 END) + 
          (CASE WHEN d5 THEN 1 ELSE 0 END) + 
          (CASE WHEN d6 THEN 1 ELSE 0 END) + 
          (CASE WHEN d7 THEN 1 ELSE 0 END) + 
          (CASE WHEN e1 THEN 1 ELSE 0 END) + 
          (CASE WHEN e2 THEN 1 ELSE 0 END) + 
          (CASE WHEN e3 THEN 1 ELSE 0 END) + 
          (CASE WHEN f1 THEN 1 ELSE 0 END) + 
          (CASE WHEN f2 THEN 1 ELSE 0 END)
      ) * 1.0 / (
          CASE
              WHEN stc IS NULL AND drv IS NULL THEN 21
              WHEN stc IS NOT NULL AND drv IS NULL THEN 22
              WHEN stc IS NULL AND drv IS NOT NULL THEN 22
              ELSE 23
          END
      ) * 100, 0) AS checked_percentage,
        TO_CHAR(cosd, 'MM/DD/YY') AS cosd,
        TO_CHAR(edit_timestamp, 'MM/DD/YY') AS edit_timestamp 
      FROM projects
      WHERE project_name = $1
    `, [projectName]);

    // Check if the result contains data
    if (result.rows.length > 0) {
      const project = result.rows[0];
      res.render("Logged-In/viewproject.ejs", { 
        projectName: projectName,
        project: project,
        currentPage: "activeprojects",
        userId: userId // Add userId here
      });
    } else {
      // If no data found for the project name, return an error response
      alert("Project not found");
    }
  } catch (error) {
    console.error("Error fetching project details:", error);
    alert("Error fetching project details");
  }
});


//Delete Project
app.post("/Logged-In/delete", async (req, res) => {
  const { password, projectNameDelete } = req.body;

  try {
    // Retrieve the user's stored password from the database
    const result = await db.query("SELECT password FROM users WHERE email = $1", [req.session.user.email]);
    if (result.rows.length === 0) {
      // User not found
      req.session.projectNotFound = true;
      return res.status(400).redirect("/Logged-In/myprojects"); // Redirect to reload the page with status 400
    }

    const userPassword = result.rows[0].password;

    // Compare the entered password with the user's encrypted password using bcrypt
    const passwordMatch = await bcrypt.compare(password, userPassword);
    if (!passwordMatch) {
      // If passwords don't match, return an error response
      req.session.incorrectPassword = true;
      return res.status(400).redirect("/Logged-In/myprojects"); // Redirect to reload the page with status 400
    }

    // If passwords match, proceed with deleting the project
    const deleteResult = await db.query("DELETE FROM projects WHERE project_name = $1", [projectNameDelete]);
    if (deleteResult.rowCount === 1) {
      // Successfully deleted the project
      res.redirect("/Logged-In/myprojects");
    } else {
      // Project not found or not deleted
      req.session.projectNotFound = true;
      return res.status(400).redirect("/Logged-In/myprojects"); // Redirect to reload the page with status 400
    }
  } catch (err) {
    console.error(err);
    // Handle any errors that occur during the deletion process
    return res.status(500).redirect("/Logged-In/myprojects"); // Redirect to reload the page with status 500
  }
});


//Review Project
app.get("/Logged-In/review", async (req, res) => {
  let incorrectPassword = req.session.incorrectPassword || false;

  req.session.incorrectPassword = false;

  try {
    const result = await db.query(`
    SELECT 
    p.project_name, 
    TO_CHAR(p.cosd, 'MM/DD/YY') AS cosd,
    TO_CHAR(p.edit_timestamp, 'MM/DD/YY') AS edit_timestamp,
    CONCAT(u.fname, ' ', LEFT(u.lname, 1), '.') AS running_by,
    p.d7 AS is_d7_null
FROM 
    projects p
INNER JOIN 
    users u ON p.user_email = u.email
WHERE 
    p.d7 IS NULL
    AND p.d1 = true
    AND p.d2 = true
    AND p.d3 = true
    AND p.d4 = true
    AND p.d5 = true
    AND p.d6 = true;
    `);
    const projects = result.rows;

    res.render("Logged-In/review.ejs", {
      listProjects: projects,
      currentPage: "review",
      incorrectPassword
    });

    // Clear the session variable after rendering the page
    req.session.incorrectPassword = false;
  } catch (err) {
    console.log(err);
  }
});

//Approve DDSS Documents
// Route to handle password submission
app.post('/submitPassword', async (req, res) => {
  const { projectName, password } = req.body;

  try {
    // Fetch user's encrypted password from the database
    const result = await db.query("SELECT password FROM users WHERE email = $1", [req.session.user.email]);
    if (result.rows.length > 0) {
      const encryptedPassword = result.rows[0].password;

      // Compare entered password with the encrypted password using bcrypt
      const passwordMatch = await bcrypt.compare(password, encryptedPassword);
      if (passwordMatch) {
        // Password matched, update project and send success response
        await db.query(`UPDATE projects SET d7 = true WHERE project_name = $1`, [projectName]);
        res.redirect("/Logged-In/review");
      } else {
        // Password didn't match, set session variable for incorrect password
        req.session.incorrectPassword = true;
        return res.status(400).redirect("/Logged-In/review");
      }
    } else {
      // User not found, send failure response
      res.status(401).json({ success: false, message: 'KeepUp Error. User not found' });
    }
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


//Transfer Project Ownership
app.post('/updateUserEmail', async (req, res) => {
  const { userEmail, projectName } = req.body;

  try {
      // Update the user email in the projects table
      await db.query('UPDATE projects SET user_email = $1 WHERE project_name = $2', [userEmail, projectName]);

      // Retrieve recipient's name from the users table
      const recipientResult = await db.query('SELECT fname, lname FROM users WHERE email = $1', [userEmail]);
      const recipient = recipientResult.rows[0];
      const recipientName = recipient ? `${recipient.fname} ${recipient.lname.charAt(0)}.` : 'Unknown';

      // Add a comment to the project indicating the change in project ownership
      const userId = req.session.user.id; // Assuming user ID is stored in session
      const userResult = await db.query('SELECT fname, lname FROM users WHERE id = $1', [userId]);
      const user = userResult.rows[0];
      const senderName = user ? `${user.fname} ${user.lname.charAt(0)}.` : 'Anonymous';
      
      const commentText = `Project ownership transferred from ${senderName} to ${recipientName}`;
      await db.query('INSERT INTO comments (project_name, user_id, user_name, comment_text) VALUES ($1, $2, $3, $4)', [projectName, userId, senderName, commentText]);

      res.redirect('/Logged-In/dashboard'); // Redirect to home page or wherever you want
  } catch (error) {
      console.error('Error updating user email:', error);
      alert("Error updating user email");
  }
});

// Comment Section
app.post('/save-comment', async (req, res) => {
  const { projectName, commentText } = req.body;
  const userId = req.session.user.id; // Assuming user ID is stored in session

  try {
      // Retrieve user's first name and last initial from the database
      const userResult = await db.query('SELECT fname, lname FROM users WHERE id = $1', [userId]);
      const user = userResult.rows[0];
      const userName = user ? `${user.fname} ${user.lname.charAt(0)}.` : 'Anonymous';

      // Insert the comment into the database
      await db.query('INSERT INTO comments (project_name, user_id, user_name, comment_text) VALUES ($1, $2, $3, $4)', [projectName, userId, userName, commentText]);
      res.json({ success: true });
  } catch (error) {
      console.error('Error saving comment:', error);
      res.status(500).json({ success: false });
  }
});

// Express route to get comments for a project
app.get('/comments', async (req, res) => {
    const projectName = req.query.projectName;
    try {
        // Retrieve comments for the specified project from the database
        const result = await db.query('SELECT * FROM comments WHERE project_name = $1', [projectName]);
        res.json({ comments: result.rows });
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

//Deleting the Comment
// Express route to delete a comment
app.delete('/delete-comment', async (req, res) => {
  const commentId = req.query.id;
  try {
      // Delete the comment from the database
      await db.query('DELETE FROM comments WHERE comment_id = $1', [commentId]);
      res.json({ success: true });
  } catch (error) {
      console.error('Error deleting comment:', error);
      res.status(500).json({ success: false });
  }
});

app.get("/Logged-In/settings", async (req, res) => {
  try {
    let successMessage = ""; // Initialize an empty success message

    // Check if the success message query parameter is present in the URL
    if (req.query.successMessage) {
      successMessage = req.query.successMessage; // Assign the success message from the query parameter
    }

    // Assuming you have a function to query the user's information from the database
    const userInfo = await db.query(`
      SELECT fname, lname, email 
      FROM users 
      WHERE id = $1
    `, [req.session.user.id]);

    if (userInfo.rows.length > 0) {
      const { fname, lname, email } = userInfo.rows[0];
      res.render("Logged-In/settings.ejs", { 
        currentPage: "settings", 
        fname: fname, 
        lname: lname, 
        email: email,
        successMessage: successMessage // Pass the success message to the template
      });
    } else {
      // Handle case where user information is not found
      res.status(404).send("User not found");
    }
  } catch (error) {
    console.error("Error fetching user information:", error);
    alert("Error fetching user information");
  }
});

//Edit User Info
// POST route to handle form submission for editing user info
app.post("/edituserinfo", async (req, res) => {
  const { firstName, lastName, email } = req.body; // Extract user input from the form
  const userId = req.session.user.id; // Get the user's ID from the session

  try {
    // Update the user information in the database
    const result = await db.query(`
      UPDATE users
      SET fname = $1, lname = $2, email = $3
      WHERE id = $4
    `, [firstName, lastName, email, userId]);

    // Check if the update was successful
    if (result.rowCount > 0) {
      // Redirect to settings page with a success message
      res.redirect("/Logged-In/dashboard");
    } else {
      // If no rows were affected, redirect with an error message
      res.redirect("/Logged-In/settings?error=true");
    }
  } catch (error) {
    console.error("Error updating user info:", error);
    // Redirect to settings page with an error message
    res.redirect("/Logged-In/settings?error=true");
  }
});



app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
