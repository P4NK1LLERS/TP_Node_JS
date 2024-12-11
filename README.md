1. Créer le dossier du projet

2. Initialiser `npm` dans le projet avec la commande `npm init`

3. Installer **express** et **nodemon** (en dev uniquement -> `npm install -D`) avec `npm install`

4. Initialiser le dépôt Git et ajouter le `.gitignore` pour ignorer le dossier `node_modules`

5. Ajouter le script dev dans le `package.json` pour lancer automatiquement avec nodemon

```json
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon index.js"
  },
```

Puis utiliser `npm run dev` pour lancer le script

6. Créer le fichier `index.js` avec le code nécessaire

7. Créer une route `/files` en **GET** permettant de récupérer la liste des fichiers présents dans un dossier de votre choix avec leurs dates de modification et leurs poids

8. Créer une route `/day-of-the-year` en **GET** permettant d'afficher le jour de l'année avec la fonction vue la semaine dernière

```
npm install --save mysql2/promise
```

```
docker run -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=Passw0rd \
  -e MYSQL_USER=admin \
  -e MYSQL_DATABASE=api \
  -e MYSQL_PASSWORD=Passw0rd \
  -d mysql

```

````
ALTER TABLE users ADD UNIQUE (email);
```
````

## Ajout de l'authentification

# Mise à jour de la table users

Ajout d'une colonne `password`

```
ALTER TABLE users ADD COLUMN password VARCHAR(255);
```

# Modification de la route POST /users pour enregistrer le mot de passe à la création de l'utilisateur

...

# Création d'une route POST /login pour s'authentifier

On attend une requête JSON avec email + password
(pensez à utiliser un schema de validation de données)

On vérifie en base de données si email + password sont OK
Renvoyer OK si tout est bon, KO sinon

Générer un token au format JWT (Json Web Token) et le renvoyer à l'utilisateur
