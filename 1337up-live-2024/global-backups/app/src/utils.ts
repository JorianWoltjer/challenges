import { normalize } from "path";

export function sanitize(s: string): string {
  s = s.replace(/[#;`$|&<>'"\\]/g, "");

  if (s.startsWith("/")) {
    s = normalize(s);
  } else {
    s = normalize("/" + s).slice(1);
  }

  if (["", ".", "..", "/"].includes(s)) {
    throw new Error("Invalid input!");
  } else {
    return s;
  }
}

export function sizeToString(size: number): string {
  if (size < 1024) {
    return size + "B";
  } else if (size < 1024 * 1024) {
    return (size / 1024).toFixed(1) + "KB";
  } else if (size < 1024 * 1024 * 1024) {
    return (size / 1024 / 1024).toFixed(1) + "MB";
  } else {
    return (size / 1024 / 1024 / 1024).toFixed(1) + "GB";
  }
}

export function timeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);

  if (seconds < 60) {
    return seconds + " seconds ago";
  } else if (seconds < 60 * 60) {
    return Math.floor(seconds / 60) + " minutes ago";
  } else if (seconds < 60 * 60 * 24) {
    return Math.floor(seconds / 60 / 60) + " hours ago";
  } else {
    return Math.floor(seconds / 60 / 60 / 24) + " days ago";
  }
}
