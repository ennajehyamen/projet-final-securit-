const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const sanitizeHtml = require("sanitize-html");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-replace",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production" },
  })
);

const mongoUrl = process.env.MONGO_URL || "mongodb://mongo:27017/fixddb";
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  username: String,
  passwordHash: String,
  searches: [{ text: String, date: Date }],
});
const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => res.redirect("/search"));

app.get("/register", (req, res) => res.render("register", { error: null }));
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.render("register", { error: "Champ manquant" });
  const exist = await User.findOne({ username });
  if (exist) return res.render("register", { error: "Utilisateur existe" });
  const saltRounds = 12;
  const ph = await bcrypt.hash(password, saltRounds);
  const u = new User({ username, passwordHash: ph, searches: [] });
  await u.save();
  req.session.userId = u._id;
  res.redirect("/search");
});

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ username });
  if (!u) return res.render("login", { error: "Mauvais identifiants" });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.render("login", { error: "Mauvais identifiants" });
  req.session.userId = u._id;
  res.redirect("/search");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  req.user = await User.findById(req.session.userId);
  if (!req.user) return res.redirect("/login");
  next();
}

app.get("/search", requireAuth, (req, res) => {
  // safe render: use escaped <%= %>; data sanitized when stored
  res.render("search", { user: req.user, q: "" });
});

app.post("/search", requireAuth, async (req, res) => {
  let q = req.body.q || "";
  // SANITIZE before storing: remove tags and attributes
  q = sanitizeHtml(q, { allowedTags: [], allowedAttributes: {} });
  req.user.searches.push({ text: q, date: new Date() });
  await req.user.save();
  res.redirect("/search");
});

const port = 3000;
app.listen(port, "0.0.0.0", () => console.log(`Listening on ${port}`));
