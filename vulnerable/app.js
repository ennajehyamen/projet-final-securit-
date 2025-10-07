const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const path = require("path");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware pour parser les cookies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const mongoUrl = process.env.MONGO_URL || "mongodb://mongo:27017/vulndb";
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });

// Mongoose models
const userSchema = new mongoose.Schema({
  username: String,
  // VULN: mot de passe stocké en clair (intentionnel pour le TP)
  password: String,
  searches: [{ text: String, date: Date }],
});
const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => {
  res.redirect("/search");
});

// Page register
app.get("/register", (req, res) => res.render("register", { error: null }));
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.render("register", { error: "Champ manquant" });
  const exist = await User.findOne({ username });
  if (exist) return res.render("register", { error: "Utilisateur existe" });
  const u = new User({ username, password, searches: [] }); // password stored plaintext -> vuln
  await u.save();

  // SÉCURISÉ: Cookie avec toutes les protections
  res.cookie("user_id", u._id.toString());

  res.redirect("/search");
});

// Login
app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ username, password }); // VULN: plain password comparison
  if (!u) return res.render("login", { error: "Mauvais identifiants" });

  // SÉCURISÉ: Cookie avec toutes les protections
  res.cookie("user_id", u._id.toString());

  res.redirect("/search");
});

// Logout
app.get("/logout", (req, res) => {
  res.clearCookie("user_id");
  res.redirect("/login");
});

// Middleware require auth
async function requireAuth(req, res, next) {
  const userId = req.headers.cookie
    ?.split(";")
    .find((cookie) => cookie.trim().startsWith("user_id="))
    ?.split("=")[1];

  if (!userId) return res.redirect("/login");

  req.user = await User.findById(userId);
  if (!req.user) return res.redirect("/login");

  next();
}

// Search page
app.get("/search", requireAuth, (req, res) => {
  res.render("search", { user: req.user, q: "" });
});

app.post("/search", requireAuth, async (req, res) => {
  const q = req.body.q || "";
  // Sauvegarde de la recherche (vulnérable à XSS stocké)
  req.user.searches.push({ text: q, date: new Date() });
  await req.user.save();
  res.redirect("/search");
});

// Start
const port = 3000;
app.listen(port, "0.0.0.0", () => console.log(`Listening on ${port}`));
