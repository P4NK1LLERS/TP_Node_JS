import "dotenv/config";

import express from "express";
import fs from "fs";
import z from "zod";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { connectDb } from "./lib.js";
import { validateData, logger, checkAuth } from "./middleware.js";

const app = express();
const currentPath = process.cwd();

let db = await connectDb();

// Créer une route /users/:id qui renvoie uniquement l'utilisateur avec l'id correspondant
// Renvoyer un code 404 si l'utilisateur n'existe pas
app.get("/users/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "SELECT id, name, email FROM users WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("User not found");
    return;
  }

  res.json(rows[0]);
});

// Créer une route POST /users qui permet d'ajouter un utilisateur avec les informations fournies
// au format JSON : name et email --
const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.string()
});

app.post(
  "/auth/signup",
  express.json(),
  validateData(userSchema),
  async (req, res) => {
    const data = req.body;
    
    if (data.role !== "formateur" && data.role !== "étudiant") {
      return res.status(400).json({ error: "Role must be 'formateur' or 'étudiant'" });
    }
    
    try {
      const hashedPassword = await bcrypt.hash(data.password, 10);
      const [result] = await db.execute(
        "INSERT INTO Utilisateur (name, email, password, role) VALUES (?, ?, ?, ?)",
        [data.name, data.email, hashedPassword , data.role]
      );

      res.status(200);
      res.json({ id: result.insertId, name: data.name, email: data.email , role: data.role});
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

// On attend comme sortie un mot de passe et un email 
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});


// ################################## Connexion et création du Token JWT ####################################

// Route POST /login pour s'authentifier
app.post(
  "/auth/login",
  express.json(),
  validateData(loginSchema),
  async (req, res) => {
    const data = req.body;

    // On vérifie en base de données si email + password sont OK
    const [rows] = await db.query(
      "SELECT id, password , role FROM Utilisateur WHERE email = ?",
      [data.email]
    );

    if (rows.length === 0) {
      res.status(401);
      res.send("Unauthorized");
      return;
    
    }

    //Comparer le mot de passe de la base de données et celui donné dans la requête
    const isRightPassword = await bcrypt.compare(
      data.password,
      rows[0].password
    );
    if (!isRightPassword) {
      res.status(401);
      res.send("Unauthorized");
      return;
    }

    // Générer un token JWT
    const payload = { id: rows[0].id , role: rows[0].role };
    const token = jwt.sign(payload, process.env.JWT_KEY);

    // Renvoyer le token si tout est OK
    res.json({ token });
  }
);

app.get("/me", logger, checkAuth, (req, res) => {
  console.log("Utilisateur authentifié", req.user);
  res.json(req.user);
});

// Route GET /protected pour tester le token
app.get("/protected", logger, checkAuth, (req, res) => {
  res.send("OK");
});

const sessionsSchema = z.object({
  title: z.string(),
  date: z.string()
});

// Route POST permettant de créer une session 
app.post("/AddSessions",express.json(),validateData(sessionsSchema), checkAuth,
  async (req, res) => {
    const data = req.body;
    const user_id = req.user.id;
    const user_role = req.user.role;
    
    //On vérifie que le rôle de la personne qui se connecte soit bien Formateur afin de lui accorder l'accès
    
    if(user_role != "formateur"){
      res.status(401);
      res.json({message: "Unauthorized, need --> role: 'formateur'"});
      return;
    }
    
    // On insère les données dans la base de données
    const [result] = await db.execute(
      "INSERT INTO Session (title, date, formateur_id) VALUES (?, ?, ?)",
      [data.title, data.date, user_id]
    );  
    res.status(200);
    res.json({ id: result.insertId, title: data.title, date: data.date, formateur_id: user_id });
    
  });

// Route GET permettant de récupérer une liste de toutes les sessions.
app.get("/GetSessions",
async (req, res) => {
  const [result] = await db.execute("SELECT * FROM Session",);
  res.status(200);
  res.json({sessions: result});
  
});

// Route GET permettant de récupérer une séssion précise avec son ID 
app.get("/GetSessions/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "SELECT id, title, date , formateur_id FROM Session WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("Session not found");
    return;
  }

  res.json(rows[0]);
});

//Création d'un schéma pour pouvoir modifier une session 

const ModifySchema = z.object({
  title: z.string().min(2),
  date: z.string(),
});

//Route PUT permetttant de modifier une session en utilisant un ID précis 
// On ajoute check auth afin de récupérer le role dans le token afin de pouvoir autoriser les accès a qui de droit 
app.put("/ModifySessions/:id(\\d+)",express.json(),validateData(ModifySchema),checkAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const data = req.body;;
  
  const user_role = req.user.role;
    
    if(user_role != "formateur"){
      res.status(401);
      res.json({message: "Unauthorized, need --> role: 'formateur'"});
      return;
    }
  
  const [result] = await db.query(
    "UPDATE Session SET title = ? , date = ?  WHERE id = ?",
    [data.title, data.date , id]
  );
  
  res.json("Session bien modifiée");
});

//Route DELETE permettant de supprimer une session deja existante

app.delete("/DeleteSessions/:id(\\d+)",checkAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  
  const user_role = req.user.role;
    
  //Verification du rôle pour donner les droits  
  
  if(user_role != "formateur"){
      res.status(401);
      res.json({message: "Unauthorized, need --> role: 'formateur'"});
      return;
    }
  
  const [rows] = await db.query(
    "DELETE FROM Session WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("Session not found");
    return;
  }

  res.json(rows[0]);
});

const SignSchema = z.object({
  status: z.number(),
});

//Route POST permettant d'emarger à une session précise en rentrant son ID 

app.post("/SignSessions/:id(\\d+)",express.json(),validateData(SignSchema),checkAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const data = req.body;;
  
  const user_role = req.user.role;
  const user_id = req.user.id;
    
    if(user_role != "etudiant"){
      res.status(401);
      res.json({message: "Unauthorized, need --> role: 'etudiant'"});
      return;
    }
  
  const [result] = await db.query(
    "INSERT INTO Emargement (session_id , etudiant_id , status) VALUES (?,?,?)",
    [id , user_id , data.status]
  );
  
  res.status(200);
  res.json("Session bien emargée");
});


//Route permettant d'avoir accès à tous les utilisateurs qui ont signés à une session 
app.get("/Sessions/:id(\\d+)/emargement",express.json(),checkAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const data = req.body;;
  
  const user_role = req.user.role;
  const user_id = req.user.id;
    
    if(user_role != "formateur"){
      res.status(401);
      res.json({message: "Unauthorized, need --> role: 'formateur'"});
      return;
    }
  
  const [rows] = await db.query(
    "SELECT Utilisateur.id , name , email  FROM Utilisateur INNER JOIN Emargement ON Utilisateur.id = Emargement.etudiant_id WHERE session_id = ?",
    [id]
  );
  
  res.status(200);
  res.json([rows]);
});


app.listen(8080, () => {
  console.log("Server is running on port 8080");
});
