import express from "express";
import session from "express-session";
import fileUpload from "express-fileupload";
import FileStore_ from "session-file-store";
import { readdir, unlink, stat } from "fs/promises";
import path from "path";

import routes from "./routes";

const PORT = 8000;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public", { maxAge: 1000 * 60 * 60 }));
app.use(fileUpload());
app.set("view engine", "ejs");

const FileStore = FileStore_(session);

app.use(
  session({
    store: new FileStore({
      path: "/tmp/sessions",
      ttl: 60,
      reapInterval: 60,
    }),
    secret: Bun.env.SECRET,
    resave: true,
    saveUninitialized: true,
  })
);

declare module "bun" {
  interface Env {
    SECRET: string;
    ADMIN_PASSWORD: string;
  }
}

declare module "express-session" {
  interface SessionData {
    username: string;
    flash: Array<string>;
  }
}

declare global {
  namespace Express {
    interface Request {
      flash(message: string): void;
    }
  }
}

app.use((req, res, next) => {
  // Flash messages
  req.flash = function (message: string) {
    if (!req.session?.flash) req.session.flash = [];
    req.session.flash?.push(message);
  };

  const render = res.render;
  res.render = function (...args) {
    if (req.session) {
      res.locals.flash = req.session.flash || [];
      req.session.flash = [];
    } else {
      res.locals.flash = [];
    }
    // @ts-ignore: Target allows only 2 element(s) but source may have more
    render.apply(res, args);
  };
  next();
});

setInterval(async () => {
  // Clean up old files (last accessed more than 5 minutes ago)
  for (const file of await readdir("/tmp/files", { recursive: true, withFileTypes: true })) {
    if (file.isFile()) {
      const fullPath = path.join("/tmp/files", file.name);
      if ((await stat(fullPath)).atimeMs < Date.now() - 5 * 60 * 1000) {
        await unlink(fullPath);
        console.log(`Purged ${fullPath}`);
      }
    }
  }
}, 60 * 1000);

app.use("/", routes);

app.listen(PORT, function () {
  console.log(`Listening at http://localhost:${PORT}`);
});
