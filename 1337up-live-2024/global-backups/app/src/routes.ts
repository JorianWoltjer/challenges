import { $ } from "bun";
import { readdir, mkdir, unlink } from "fs/promises";
import express, { type NextFunction, type Request, type Response } from "express";
import "express-async-errors";
import path from "path";

import { getUser } from "./db";
import { sanitize, sizeToString, timeAgo } from "./utils";
import { stat } from "fs/promises";

const router = express.Router();

router.get("/", function (req: Request, res: Response) {
  res.render("index", { username: req.session.username });
});

// Auth

router.get("/login", function (req: Request, res: Response) {
  res.render("login");
});

router.post("/login", async function (req: Request, res: Response) {
  let { username, password } = req.body;

  if (typeof username !== "string" || typeof password !== "string") {
    res.type("txt");
    res.status(400).send("Invalid parameters!");
    return;
  }

  username = sanitize(username);
  const user = await getUser(username);

  if (user && (await Bun.password.verify(password, user.password))) {
    console.log(`User '${username}' logged in`);

    req.session.username = username;
    req.session.cookie.maxAge = 9999999999999; // Keep logged-in sessions alive
    req.flash("Successfully logged in!");
    res.redirect("/files");
  } else {
    await $`echo ${username} failed to log in >> /tmp/auth.log`;
    req.flash("Invalid username or password!");
    res.redirect("/login");
  }
});

router.use((req, res, next) => {
  // Auth middleware
  if (req.session.username) {
    req.session.username = sanitize(req.session.username);
    if (/[-\/]/.test(req.session.username)) {
      res.type("txt");
      res.status(400).send("Invalid username!");
      return;
    }
    next();
  } else {
    req.flash("You need to be logged in to access this page!");
    res.redirect("/login");
  }
});

router.get("/logout", function (req: Request, res: Response) {
  delete req.session.username;
  req.session.cookie.maxAge = 0;
  req.flash("Successfully logged out!");
  res.redirect("/");
});

// Files

router.get("/files", async function (req: Request, res: Response) {
  const dir = `/tmp/files/${req.session.username}`;
  try {
    await mkdir(dir);
  } catch {}
  const filenames = await readdir(dir);

  const files = await Promise.all(
    filenames.map(async (file) => {
      const stats = await stat(path.join(dir, file));
      const size = sizeToString(stats.size);
      const accessed = timeAgo(stats.atime);
      return { name: file, size: size, accessed };
    })
  );

  res.render("files", { files });
});

router.get("/file/:name", function (req: Request, res: Response) {
  let { name } = req.params;

  name = sanitize(name);

  res.download(`/tmp/files/${req.session.username}/${name}`);
});

router.post("/upload", async function (req: Request, res: Response) {
  const file = req.files?.file;

  if (!file || Array.isArray(file)) {
    res.type("txt");
    res.status(400).send("Invalid parameters!");
    return;
  }

  file.name = sanitize(file.name);

  await file.mv(`/tmp/files/${req.session.username}/${file.name}`);

  req.flash("File uploaded!");
  res.redirect("/files");
});

router.post("/delete/:name", async function (req: Request, res: Response) {
  let { name } = req.params;

  name = sanitize(name);

  await unlink(`/tmp/files/${req.session.username}/${name}`);

  req.flash("File deleted!");
  res.redirect("/files");
});

// Backup

router.post("/backup", async function (req: Request, res: Response) {
  const cwd = `/tmp/files/${req.session.username}`;
  const tar = (await $`echo $(mktemp -d)/backup.tar.gz`.text()).trim();
  await $`tar -czf ${tar} .`.cwd(cwd);
  await $`scp ${tar} ${req.session.username}@backup:`.cwd(cwd);

  req.flash("Files backed up!");
  res.redirect("/files");
});

router.post("/restore", async function (req: Request, res: Response) {
  const cwd = `/tmp/files/${req.session.username}`;
  const tar = "backup.tar.gz";
  await $`scp ${req.session.username}@backup:${tar} .`.cwd(cwd);
  await $`tar -xzf ${tar} && rm ${tar}`.cwd(cwd);

  req.flash("Files restored!");
  res.redirect("/files");
});

router.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  err.stack = "";
  console.error(err);
  res.type("txt");
  res.status(500).send(`${err.name}: ${err.message}`);
});

export default router;
