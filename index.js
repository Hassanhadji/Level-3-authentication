import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
});

db.connect();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));



app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {

  const username = req.body.email;
  const password = req.body.password;
try {

  const existinguser = await db.query("select id from users where username = $1", [username]);
  if ( existinguser.rows.length > 0){
    return res.status(400).json({error: "User already exists"});
  }

  const hashedPassword = await bcrypt.hash(password,10);
  const result = await db.query(
    "insert into users (username, password) values ($1,$2) returning id, username;",
    [username,hashedPassword]
  );
 

  return res.render("login.ejs");
}
catch(err){
  console.error(err);
  res.status(500).json({error : "server error"});


}
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    
    const result = await db.query(
      "SELECT id, username, password FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    
    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    return res.render("secret.ejs");

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
