import { readdir, readFile, copyFile } from "node:fs/promises";
import { join } from "node:path";

const distDir = new URL("../dist/", import.meta.url);
const assetsDir = new URL("./assets/", distDir);

const entries = await readdir(assetsDir);
const jsFiles = entries.filter((name) => name.endsWith(".js"));
const cssFiles = entries.filter((name) => name.endsWith(".css"));

let appSource = "";
for (const name of jsFiles) {
  const content = await readFile(new URL(name, assetsDir), "utf8");
  if (content.includes("Call Recording Scam Detector")) {
    appSource = name;
    break;
  }
}

if (!appSource) {
  throw new Error("Unable to locate the generated application chunk for the compatibility app.js fallback.");
}

await copyFile(new URL(appSource, assetsDir), new URL("app.js", distDir));

if (cssFiles.length) {
  await copyFile(new URL(cssFiles[0], assetsDir), new URL("styles.css", distDir));
}
