const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Путь к статическим файлам Swagger UI
const swaggerPath = path.join(__dirname, "docs");

// Маршрут для обслуживания Swagger UI
app.use("/docs", express.static(swaggerPath));

// Основная папка для статических файлов вашего приложения
app.use(express.static(path.join(__dirname, "/")));

// Все остальные маршруты отправляют index.html
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"), (err) => {
        if (err) {
            res.status(500).send(err);
        }
    });
});

app.listen(PORT, () => {
    console.log(`Frontend server is running at http://localhost:${PORT}`);
});

/*
const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.static(path.join(__dirname, "/")));

app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "/", "index.html"));
});

app.listen(PORT, () => {
    console.log(`Frontend server is running at http://localhost:${PORT}`);
});*/
